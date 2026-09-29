"""Phone number validation and E.164 normalisation.

No third-party dependency: WSA keeps its own dial-code table so that a number
is stored exactly once, in international form (``+250788123456``), regardless
of whether the user typed ``0788123456``, ``250788123456`` or
``+250 788 123 456``.
"""
import re

# ISO 3166-1 alpha-2 -> (dial code, label). Kept to the countries a security
# team realistically needs for SMS verification; extend as required.
COUNTRY_CODES = {
    "RW": ("+250", "Rwanda"),
    "BI": ("+257", "Burundi"),
    "CD": ("+243", "DR Congo"),
    "KE": ("+254", "Kenya"),
    "UG": ("+256", "Uganda"),
    "TZ": ("+255", "Tanzania"),
    "ET": ("+251", "Ethiopia"),
    "ZA": ("+27", "South Africa"),
    "NG": ("+234", "Nigeria"),
    "GH": ("+233", "Ghana"),
    "EG": ("+20", "Egypt"),
    "MA": ("+212", "Morocco"),
    "US": ("+1", "United States"),
    "CA": ("+1", "Canada"),
    "GB": ("+44", "United Kingdom"),
    "IE": ("+353", "Ireland"),
    "FR": ("+33", "France"),
    "DE": ("+49", "Germany"),
    "ES": ("+34", "Spain"),
    "IT": ("+39", "Italy"),
    "NL": ("+31", "Netherlands"),
    "BE": ("+32", "Belgium"),
    "CH": ("+41", "Switzerland"),
    "AT": ("+43", "Austria"),
    "SE": ("+46", "Sweden"),
    "NO": ("+47", "Norway"),
    "DK": ("+45", "Denmark"),
    "FI": ("+358", "Finland"),
    "PL": ("+48", "Poland"),
    "PT": ("+351", "Portugal"),
    "AE": ("+971", "UAE"),
    "SA": ("+966", "Saudi Arabia"),
    "QA": ("+974", "Qatar"),
    "IN": ("+91", "India"),
    "PK": ("+92", "Pakistan"),
    "BD": ("+880", "Bangladesh"),
    "CN": ("+86", "China"),
    "JP": ("+81", "Japan"),
    "KR": ("+82", "South Korea"),
    "AU": ("+61", "Australia"),
    "NZ": ("+64", "New Zealand"),
    "BR": ("+55", "Brazil"),
}

# Longest first so "+250" wins over "+25".
_SORTED_DIAL_CODES = sorted({cc for cc, _ in COUNTRY_CODES.values()}, key=len, reverse=True)

_SEPARATORS = re.compile(r"[\s\-()./ ]")
_DIGITS = re.compile(r"^\d+$")

MIN_NSN = 6
MAX_NSN = 14  # E.164 allows 15 digits including the country code


class PhoneError(ValueError):
    """Raised with a user-safe message when a number cannot be normalised."""


def country_options():
    """[(iso, dial_code, label)] for the registration country selector."""
    return [(iso, cc, label) for iso, (cc, label) in sorted(
        COUNTRY_CODES.items(), key=lambda kv: (kv[1][1], kv[0]))]


def default_country():
    return "RW"


def _strip(raw):
    value = (raw or "").strip()
    value = _SEPARATORS.sub("", value)
    return value


def normalize(raw, country_iso=None):
    """Return the E.164 form of ``raw``.

    Raises :class:`PhoneError` with a safe message on anything unparseable.
    """
    value = _strip(raw)
    if not value:
        raise PhoneError("Enter a phone number.")

    explicit_plus = value.startswith("+") or value.startswith("00")
    if value.startswith("00"):
        value = "+" + value[2:]
    elif value.startswith("+"):
        pass

    if not _DIGITS.match(value.lstrip("+")):
        raise PhoneError("Phone numbers may only contain digits, spaces, + and -.")

    dial = None
    if not explicit_plus:
        # A bare national number needs its country to be disambiguated.
        if country_iso and country_iso.upper() in COUNTRY_CODES:
            dial = COUNTRY_CODES[country_iso.upper()][0]
        else:
            dial = _guess_dial_code(value.lstrip("+"))
            if dial is None:
                raise PhoneError("Select your country so the number can be normalised.")

    national = value.lstrip("+")
    if dial and not explicit_plus:
        if national.startswith(dial.lstrip("+")) and len(national) > len(dial.lstrip("+")):
            national = national[len(dial.lstrip("+")):]  # already carried the country code
        elif national.startswith("0"):
            national = national[1:]  # strip the national trunk prefix
        elif not _looks_like_nsn(national):
            raise PhoneError("Enter a valid phone number.")
        e164 = dial + national
    else:
        e164 = "+" + national
        if not _looks_like_nsn(national):
            raise PhoneError("Enter a valid phone number.")

    if not e164.startswith("+") or not _looks_like_nsn(e164[1:]):
        raise PhoneError("Enter a valid international phone number.")
    return e164


def _looks_like_nsn(digits):
    return digits.isdigit() and MIN_NSN <= len(digits) <= MAX_NSN and not digits.startswith("0")


def _guess_dial_code(digits):
    """Infer a dial code from a number typed without '+' (e.g. 250788123456)."""
    for code in _SORTED_DIAL_CODES:
        bare = code.lstrip("+")
        if digits.startswith(bare):
            rest = digits[len(bare):]
            if _looks_like_nsn(rest) and not digits.startswith("0"):
                return code
    return None


def is_valid(raw, country_iso=None):
    try:
        normalize(raw, country_iso)
        return True
    except PhoneError:
        return False


def mask_phone(value):
    """``+250788123456`` -> ``+250 *** *** 456`` (never show a full number)."""
    if not value:
        return ""
    text = str(value).strip()
    if not text.startswith("+") or len(text) < 5:
        digits = "".join(ch for ch in text if ch.isdigit())
        return ("***" + digits[-2:]) if len(digits) >= 2 else "***"
    cc, national = text[: text.index("+") + 4], text[text.index("+") + 4:]
    if len(national) <= 3:
        return cc + " *** " + national[-2:] if national else cc + " ***"
    return f"{cc} *** *** {national[-3:]}"


def same_number(a, b):
    try:
        return normalize(a) == normalize(b)
    except PhoneError:
        return False
