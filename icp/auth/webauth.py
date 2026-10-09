"""idmsa.apple.com web-session login - a second Apple auth surface (the icloud.com browser
flow), separate from the device GSA flow. It cannot join the Octagon circle, but it reaches
web-scoped webservices the device path never sees - `premiummailsettings` (Hide My Email).
SRP-6a, same variant as gsa.py. See RESEARCH.md "Hide My Email"."""

from __future__ import annotations

import base64
import hashlib
import json
import logging

import requests
import srp._pysrp as srp

from ..errors import AppleError
from .. import diag, tls

log = logging.getLogger(__name__)

srp.rfc5054_enable()
srp.no_username_in_x()

AUTH_ENDPOINT = "https://idmsa.apple.com/appleauth/auth"
SETUP_ENDPOINT = "https://setup.icloud.com/setup/ws/1"
ICLOUD_ORIGIN = "https://www.icloud.com"

# icloud.com's public OAuth widget key (not account-specific).
WIDGET_KEY = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d"

_USER_AGENT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/18.3.1 Safari/605.1.15")

_SRP_N_LEN = 256  # 2048-bit group -> 256-byte fixed-width values on the wire

# Response headers Apple uses to thread session state across calls -> our session_data keys.
_HEADER_DATA = {
    "X-Apple-ID-Account-Country": "account_country",
    "X-Apple-ID-Session-Id": "session_id",
    "X-Apple-Session-Token": "session_token",
    "X-Apple-TwoSV-Trust-Token": "trust_token",
    "X-Apple-Auth-Attributes": "auth_attributes",
    "scnt": "scnt",
}


class WebAuthError(AppleError):
    pass


def _derive_password_key(password: str, salt: bytes, iterations: int, protocol: str) -> bytes:
    """Apple's pre-SRP password KDF, identical to gsa.py's `_encrypt_password`."""
    p = hashlib.sha256(password.encode("utf-8")).digest()
    if protocol == "s2k_fo":
        p = p.hex().encode("utf-8")
    return hashlib.pbkdf2_hmac("sha256", p, salt, iterations, 32)


def _reason(data) -> str | None:
    """Extract Apple's error text from a JSON error body (failure regardless of HTTP status)."""
    if not isinstance(data, dict):
        return None
    reason = data.get("errorMessage") or data.get("reason") or data.get("errorReason")
    if not reason and isinstance(data.get("error"), str):
        reason = data["error"]
    return reason


class WebAuthSession:
    """One idmsa web-session login. `export()` / the constructor's `session_data`/`cookies` are
    the persistable state (a saved trust token then skips 2FA). `frame_tag` is a random
    per-session `auth-<uuid>` threaded through the OAuth headers - generate once, persist, reuse."""

    def __init__(self, frame_tag: str, session_data: dict | None = None,
                cookies: dict | None = None):
        self.frame_tag = frame_tag
        self.session_data = dict(session_data or {})
        self.needs_2fa = False
        self.http = requests.Session()
        self.http.verify = tls.ca_bundle()
        self.http.headers["User-Agent"] = _USER_AGENT
        if cookies:
            requests.utils.add_dict_to_cookiejar(self.http.cookies, cookies)

    def export(self) -> dict:
        return {"frame_tag": self.frame_tag, "session_data": self.session_data,
                "cookies": requests.utils.dict_from_cookiejar(self.http.cookies)}

    def _auth_headers(self) -> dict:
        """For idmsa.apple.com calls: federate, signin/init, signin/complete, 2FA, trust."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://idmsa.apple.com",
            "Referer": "https://idmsa.apple.com/",
            "X-Apple-Widget-Key": WIDGET_KEY,
            "X-Apple-OAuth-Client-Id": WIDGET_KEY,
            "X-Apple-OAuth-Client-Type": "firstPartyAuth",
            "X-Apple-OAuth-Redirect-URI": ICLOUD_ORIGIN,
            "X-Apple-OAuth-Require-Grant-Code": "true",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-OAuth-State": self.frame_tag,
            "X-Apple-Frame-Id": self.frame_tag,
            "X-Requested-With": "XMLHttpRequest",
            "X-Apple-Mandate-Security-Upgrade": "0",
            "X-Apple-I-Require-UE": "true",
        }
        if self.session_data.get("auth_attributes"):
            headers["X-Apple-Auth-Attributes"] = self.session_data["auth_attributes"]
        if self.session_data.get("scnt"):
            headers["scnt"] = self.session_data["scnt"]
        if self.session_data.get("session_id"):
            headers["X-Apple-ID-Session-Id"] = self.session_data["session_id"]
        return headers

    def _setup_headers(self) -> dict:
        """For setup.icloud.com calls: accountLogin, validate - a different origin, so a
        different Origin/Referer than the idmsa calls above."""
        return {"Content-Type": "application/json", "Origin": ICLOUD_ORIGIN,
                "Referer": ICLOUD_ORIGIN + "/"}

    def _capture(self, resp: requests.Response) -> None:
        # Redacted request/response trail for `--debug` transcripts (diag.start()).
        log.debug("%s %s -> HTTP %s; headers=%s", resp.request.method,
                  resp.request.path_url.split("?")[0], resp.status_code,
                  sorted(h for h in resp.headers if h in _HEADER_DATA or h.startswith("X-Apple")))
        body = self._json_or_none(resp)
        if body is not None:
            diag.dump(log, f"{resp.request.method} {resp.request.path_url.split('?')[0]} body", body)
        for header, key in _HEADER_DATA.items():
            if resp.headers.get(header):
                self.session_data[key] = resp.headers[header]

    def _get(self, url: str, *, headers: dict, params: dict | None = None) -> requests.Response:
        resp = self.http.get(url, headers=headers, params=params, timeout=20)
        self._capture(resp)
        return resp

    def _post(self, url: str, *, headers: dict, params: dict | None = None,
              body: dict | None = None) -> requests.Response:
        data = json.dumps(body) if body is not None else None
        resp = self.http.post(url, headers=headers, params=params, data=data, timeout=20)
        self._capture(resp)
        return resp

    def _json_or_none(self, resp: requests.Response):
        try:
            return resp.json()
        except ValueError:
            return None

    def _auth_start(self) -> None:
        """GET .../authorize/signin - loads the widget and sets the idmsa session cookies
        (e.g. `aasp`) the rest of the flow needs."""
        params = {
            "frame_id": self.frame_tag, "language": "en_US", "skVersion": "7",
            "iframeId": self.frame_tag, "client_id": WIDGET_KEY,
            "redirect_uri": ICLOUD_ORIGIN, "response_type": "code",
            "response_mode": "web_message", "state": self.frame_tag, "authVersion": "latest",
        }
        resp = self._get(f"{AUTH_ENDPOINT}/authorize/signin",
                         headers={"Accept": "*/*"}, params=params)
        if not resp.ok:
            raise WebAuthError(f"could not start the web session (HTTP {resp.status_code})")

    def _federate(self, username: str) -> None:
        """POST .../federate - names the account before the SRP exchange (no password yet)."""
        resp = self._post(f"{AUTH_ENDPOINT}/federate", headers=self._auth_headers(),
                          params={"isRememberMeEnabled": "true"},
                          body={"accountName": username, "rememberMe": True})
        if not resp.ok:
            raise WebAuthError(f"federate failed (HTTP {resp.status_code})")

    def _srp_init(self, username: str, a_bytes: bytes) -> dict:
        resp = self._post(f"{AUTH_ENDPOINT}/signin/init", headers=self._auth_headers(),
                          body={"a": base64.b64encode(a_bytes).decode(),
                                "accountName": username, "protocols": ["s2k", "s2k_fo"]})
        data = self._json_or_none(resp)
        reason = _reason(data)
        if data is None or reason or not resp.ok:
            raise WebAuthError(f"SRP init failed (HTTP {resp.status_code}): "
                               f"{reason or resp.reason}")
        return data

    def signin(self, username: str, password: str, trust_token: str | None = None) -> None:
        """Full SRP-6a sign-in: authorize/signin -> federate -> signin/init -> signin/complete.
        A 409 (HSA2 challenge pending) sets `self.needs_2fa` rather than raising."""
        username = username.lower()  # Apple lowercases the account name for the SRP proof
        self._auth_start()
        self._federate(username)

        self._password = password  # in memory only, for a possible escrow proof (_escrow)
        usr = srp.User(username, bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        a_bytes = usr.A.to_bytes(_SRP_N_LEN, "big")
        init = self._srp_init(username, a_bytes)
        m1, m2 = _srp_proof(usr, password, init)

        resp = self._post(
            f"{AUTH_ENDPOINT}/signin/complete", headers=self._auth_headers(),
            params={"isRememberMeEnabled": "true"},
            body={"accountName": username, "m1": base64.b64encode(m1).decode(),
                  "m2": base64.b64encode(m2).decode(), "c": init["c"], "rememberMe": True,
                  "trustTokens": [trust_token] if trust_token else []})
        if resp.status_code == 409 and _requires_escrow(resp):
            # Since iOS 26.4: the trust token was accepted, but Apple wants the escrow proof.
            self._escrow()
            self.needs_2fa = False
            return
        if resp.status_code == 409:
            self.needs_2fa = True
            return
        self.needs_2fa = False
        if resp.ok:
            return
        data = self._json_or_none(resp)
        raise WebAuthError(f"sign-in failed (HTTP {resp.status_code}): "
                           f"{_reason(data) or resp.reason}")

    def request_push_notification(self) -> None:
        """PUT .../verify/trusteddevice/securitycode - explicitly pushes a 2FA code to trusted
        devices. Required because idmsa's SRP 409 no longer auto-triggers the push; call once
        right after `signin()` reports `needs_2fa`, before prompting for a code."""
        resp = self.http.put(f"{AUTH_ENDPOINT}/verify/trusteddevice/securitycode",
                             headers=self._auth_headers(), timeout=20)
        self._capture(resp)
        if not resp.ok:
            raise WebAuthError(f"could not request a 2FA push (HTTP {resp.status_code})")

    def submit_2fa(self, code: str) -> None:
        """POST the 6-digit HSA2 code shown on a trusted device, then request the browser
        be trusted so future logins reuse the trust token instead of re-prompting."""
        resp = self._post(f"{AUTH_ENDPOINT}/verify/trusteddevice/securitycode",
                          headers=self._auth_headers(), body={"securityCode": {"code": code}})
        data = self._json_or_none(resp)
        if resp.status_code == 409:
            # Since iOS 26.4 Apple acknowledges a *valid* code with 409 (securityCode.valid and a
            # fresh X-Apple-Session-Token, which _capture already stored); X-Apple-EDP/PDP then
            # asks for the escrow proof before the session counts as signed in.
            valid = isinstance(data, dict) and (data.get("securityCode") or {}).get("valid") is True
            if not (valid or resp.headers.get("X-Apple-Session-Token")):
                raise WebAuthError(f"2FA code rejected (HTTP 409): {_reason(data) or resp.reason}")
            if _requires_escrow(resp):
                self._escrow()
        elif not resp.ok:
            raise WebAuthError(f"2FA code rejected (HTTP {resp.status_code}): "
                               f"{_reason(data) or resp.reason}")
        trust = self._get(f"{AUTH_ENDPOINT}/2sv/trust", headers=self._auth_headers())
        if not trust.ok:
            raise WebAuthError(f"could not trust the session (HTTP {trust.status_code})")
        self.needs_2fa = False

    def _escrow(self) -> None:
        """POST escrow/init + escrow/complete - a second SRP password proof with an empty account
        name, required since iOS 26.4 when a 409 carries X-Apple-EDP/X-Apple-PDP. Like
        signin/complete, but also sends the SRP session key K; Apple answers with an updated
        session token (_capture stores it). See RESEARCH.md "Hide My Email"."""
        password = getattr(self, "_password", None)
        if not password:
            raise WebAuthError("Apple asked for the escrow password proof, but no password is "
                               "available in this session")
        usr = srp.User("", bytes(), hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        resp = self._post(f"{AUTH_ENDPOINT}/escrow/init", headers=self._auth_headers(),
                          body={"a": base64.b64encode(usr.A.to_bytes(_SRP_N_LEN, "big")).decode(),
                                "accountName": "", "protocols": ["s2k", "s2k_fo"]})
        init = self._json_or_none(resp)
        if not resp.ok or not isinstance(init, dict) or _reason(init):
            raise WebAuthError(f"escrow init failed (HTTP {resp.status_code}): "
                               f"{_reason(init) or resp.reason}")
        m1, m2 = _srp_proof(usr, password, init)
        resp = self._post(f"{AUTH_ENDPOINT}/escrow/complete", headers=self._auth_headers(),
                          body={"m1": base64.b64encode(m1).decode(),
                                "m2": base64.b64encode(m2).decode(), "c": init["c"],
                                "k": base64.b64encode(usr.K).decode()})
        if not resp.ok:
            data = self._json_or_none(resp)
            raise WebAuthError(f"escrow complete failed (HTTP {resp.status_code}): "
                               f"{_reason(data) or resp.reason}")

    def account_login(self) -> dict:
        """POST .../accountLogin using the session token from signin(). Returns the parsed
        account payload (dsInfo, webservices, hsaChallengeRequired/hsaTrustedBrowser)."""
        body = {"accountCountryCode": self.session_data.get("account_country"),
               "dsWebAuthToken": self.session_data.get("session_token"),
               "extended_login": True,
               "trustToken": self.session_data.get("trust_token", "")}
        resp = self._post(f"{SETUP_ENDPOINT}/accountLogin", headers=self._setup_headers(),
                          body=body)
        data = self._json_or_none(resp)
        if data is None:
            raise WebAuthError(f"accountLogin returned non-JSON (HTTP {resp.status_code})")
        reason = _reason(data)
        if reason or not resp.ok:
            raise WebAuthError(f"accountLogin failed (HTTP {resp.status_code}): "
                               f"{reason or resp.reason}")
        return data


def _requires_escrow(resp: requests.Response) -> bool:
    """Since iOS 26.4 a 409 carrying X-Apple-EDP or X-Apple-PDP means "now prove the password
    again via escrow/init + escrow/complete" (WebAuthSession._escrow)."""
    return bool(resp.headers.get("X-Apple-EDP") or resp.headers.get("X-Apple-PDP"))


def _srp_proof(usr, password: str, init: dict) -> tuple[bytes, bytes]:
    """Run the client side of an SRP init response ({salt, b, iteration, protocol}) -> (m1, m2).
    Leaves the session key in usr.K."""
    salt = base64.b64decode(init["salt"])
    usr.p = _derive_password_key(password, salt, init["iteration"], init["protocol"])
    m1 = usr.process_challenge(salt, base64.b64decode(init["b"]))
    if m1 is None:
        raise WebAuthError("SRP challenge processing failed (invalid server-supplied B)")
    return m1, usr.H_AMK


def hsa_challenge_required(account_data: dict) -> bool:
    """True if accountLogin still needs a 2FA code (a stale saved session accountLogin accepted
    but idmsa no longer treats as a trusted browser)."""
    ds = account_data.get("dsInfo") or {}
    return ds.get("hsaVersion", 0) == 2 and (
        account_data.get("hsaChallengeRequired", False)
        or not account_data.get("hsaTrustedBrowser", False))


def extract_webservices(account_data: dict) -> dict:
    """Flatten accountLogin's webservices map to {name: url}, e.g. 'premiummailsettings' -
    the service the device auth path's get_account_settings map never includes."""
    ws = account_data.get("webservices") or {}
    return {name: v["url"] for name, v in ws.items()
            if isinstance(v, dict) and v.get("url") and v.get("status") != "off"}
