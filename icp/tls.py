"""TLS trust for Apple endpoints.

`gsa.apple.com` (Apple ID sign-in) serves a certificate chained to Apple's own **Apple Root CA**,
which public CA bundles (certifi, the system store) do not carry, so a plain `verify=True` fails
with CERTIFICATE_VERIFY_FAILED. Upstream worked around that with `verify=False` on every sign-in
request, which turns off certificate checking entirely and exposes the password-equivalent tokens
to anyone on the network path. Here we instead verify against certifi's public roots **plus**
Apple Root CA (shipped in `icp/certs/`, pinned by SHA-256 fingerprint).

Set `ICP_CA_BUNDLE=/path/to/bundle.pem` to use your own bundle instead (corporate proxies).
"""

from __future__ import annotations

import base64
import hashlib
import importlib.resources
import os

import certifi

from . import paths

# SHA-256 of the DER certificate, as published at https://www.apple.com/certificateauthority/
APPLE_ROOT_CA_SHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"


class TLSBundleError(RuntimeError):
    pass


def apple_root_pem() -> bytes:
    """The bundled Apple Root CA, verified against its pinned fingerprint before use."""
    pem = importlib.resources.files("icp").joinpath("certs/apple-root-ca.pem").read_bytes()
    body = b"".join(
        line.strip() for line in pem.splitlines()
        if line.strip() and not line.startswith(b"-----")
    )
    der = base64.b64decode(body, validate=True)
    digest = hashlib.sha256(der).hexdigest()
    if digest != APPLE_ROOT_CA_SHA256:
        raise TLSBundleError(
            f"bundled Apple Root CA fingerprint mismatch ({digest}); refusing to trust it")
    return pem


def ca_bundle() -> str:
    """Path to a PEM bundle = certifi roots + Apple Root CA, (re)built under the icp config dir
    whenever certifi or the shipped root changes. Returns `ICP_CA_BUNDLE` verbatim if set."""
    override = os.environ.get("ICP_CA_BUNDLE")
    if override:
        return override
    with open(certifi.where(), "rb") as fh:
        public = fh.read()
    want = public.rstrip(b"\n") + b"\n\n# Apple Root CA (added by icp)\n" + apple_root_pem()
    out = paths.config_dir() / "ca-bundle.pem"
    if not out.exists() or out.read_bytes() != want:
        tmp = out.with_suffix(".pem.tmp")
        tmp.write_bytes(want)
        os.replace(tmp, out)
    return str(out)
