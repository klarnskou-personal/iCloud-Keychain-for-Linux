"""Terminal output and prompt helpers. Normal output goes to stdout; progress/warnings/errors
go to stderr so `icp ... > file` captures only the result."""
import getpass
import sys

try:
    # Line editing for input(): backspace then removes a whole character, not one byte of
    # a multibyte one like æ/ø/å, so the line we read back stays valid UTF-8.
    import readline  # noqa: F401
except ImportError:
    pass


def out(msg: str = "") -> None:
    print(msg)


def step(msg: str) -> None:
    print(msg, file=sys.stderr)


def warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def _input(msg: str) -> str:
    """input() that asks again instead of crashing when the typed line isn't valid UTF-8
    (e.g. a half-erased æ/ø/å on a terminal without readline)."""
    while True:
        try:
            return input(msg)
        except UnicodeDecodeError:
            warn("could not read that input (invalid characters) - please type it again")


def ask(msg: str) -> str:
    return _input(msg).strip()


def secret(msg: str) -> str:
    return getpass.getpass(msg)


def confirm_yn(msg: str) -> bool:
    """Yes/No prompt that defaults to No (empty or anything but y/yes)."""
    return _input(msg).strip().lower() in ("y", "yes")
