"""Pure-Python input validation helpers (no Flask dependency, easy to unit test)."""
import re
from datetime import datetime, timedelta, timezone

DEFAULT_ROLL_REGEX = r"^[A-Za-z0-9][A-Za-z0-9/_\-]{2,31}$"
DEFAULT_MOBILE_REGEX = r"^[6-9][0-9]{9}$"
USERNAME_REGEX = r"^[a-z][a-z0-9._\-]{2,31}$"

# Tiny deny-list of passwords people actually pick. Not a substitute for length/complexity rules.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "12345678", "123456789", "1234567890",
    "qwerty123", "qwertyuiop", "iloveyou", "admin123", "welcome123", "letmein123", "student123",
    "college123", "findback123", "abcd1234", "abc12345", "11111111", "00000000",
}

REPORT_LIMITS = {
    "item_name": 120,
    "description": 2000,
    "location": 200,
    "distinguishing_features": 1000,
    "private_contact": 150,
}


class ValidationError(ValueError):
    """Raised with one or more human-readable messages."""

    def __init__(self, errors):
        if isinstance(errors, str):
            errors = [errors]
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def _has_control_chars(text):
    return any(ord(c) < 32 and c not in "\n\r\t" for c in text)


def clean_text(value, max_len, field_label, required=False, multiline=False):
    value = (value or "").strip()
    if not multiline:
        value = " ".join(value.split())
    if required and not value:
        raise ValidationError(f"{field_label} is required.")
    if len(value) > max_len:
        raise ValidationError(f"{field_label} must be at most {max_len} characters.")
    if _has_control_chars(value):
        raise ValidationError(f"{field_label} contains invalid characters.")
    return value


def normalize_roll(raw, regex=DEFAULT_ROLL_REGEX):
    roll = (raw or "").strip().upper()
    if not roll:
        raise ValidationError("Roll number is required.")
    if not re.match(regex, roll, re.IGNORECASE):
        raise ValidationError(
            "Roll number must be 3-32 characters: letters, digits and - _ / only."
        )
    return roll


def normalize_mobile(raw, regex=DEFAULT_MOBILE_REGEX):
    digits = re.sub(r"[\s\-()]", "", (raw or "").strip())
    if digits.startswith("+"):
        digits = digits[1:]
    if not digits.isdigit():
        raise ValidationError("Mobile number must contain digits only.")
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if not re.match(regex, digits):
        raise ValidationError("Enter a valid 10-digit registered mobile number.")
    return digits


def normalize_name(raw):
    name = clean_text(raw, 100, "Name", required=True)
    if len(name) < 2:
        raise ValidationError("Name must be at least 2 characters.")
    if not re.search(r"[^\W\d_]", name):
        raise ValidationError("Name must contain letters.")
    if re.search(r"[<>]", name):
        raise ValidationError("Name contains invalid characters.")
    return name


def normalize_username(raw):
    username = (raw or "").strip().lower()
    if not re.match(USERNAME_REGEX, username):
        raise ValidationError(
            "Username must be 3-32 characters, start with a letter, and use only "
            "letters, digits, dot, underscore or hyphen."
        )
    return username


def validate_new_password(new_password, current_password=None, forbidden=(), min_length=8):
    """Return a list of problems (empty list = acceptable)."""
    errors = []
    pw = new_password or ""
    if len(pw) < min_length:
        errors.append(f"Password must be at least {min_length} characters long.")
    if len(pw) > 128:
        errors.append("Password must be at most 128 characters long.")
    if not re.search(r"[A-Za-z]", pw) or not re.search(r"[0-9]", pw):
        errors.append("Password must contain at least one letter and one digit.")
    if pw.strip() != pw:
        errors.append("Password must not start or end with spaces.")
    if pw.lower() in COMMON_PASSWORDS:
        errors.append("That password is too common. Choose something less guessable.")
    if current_password is not None and pw == current_password:
        errors.append("New password must be different from the current password.")
    for bad in forbidden:
        if bad and pw.lower() == str(bad).lower():
            errors.append("Password must not be your roll number, username or mobile number.")
            break
    return errors


def parse_date(raw, field_label="Date", allow_future_days=1):
    raw = (raw or "").strip()
    try:
        parsed = datetime.strptime(raw, "%Y-%m-%d")
    except ValueError:
        raise ValidationError(f"{field_label} must be a valid date (YYYY-MM-DD).")
    today = datetime.now(timezone.utc).replace(tzinfo=None)
    if parsed.date() > (today + timedelta(days=allow_future_days)).date():
        raise ValidationError(f"{field_label} cannot be in the future.")
    if parsed.year < 2000:
        raise ValidationError(f"{field_label} is too far in the past.")
    return parsed.strftime("%Y-%m-%d")


def validate_report_form(form, categories, date_label="Date"):
    """Validate lost/found report fields. Returns (cleaned_dict, errors_list)."""
    cleaned, errors = {}, []

    def grab(key, label, required=False, multiline=False):
        try:
            cleaned[key] = clean_text(form.get(key, ""), REPORT_LIMITS[key], label,
                                      required=required, multiline=multiline)
        except ValidationError as exc:
            errors.extend(exc.errors)
            cleaned[key] = (form.get(key, "") or "").strip()

    grab("item_name", "Item name", required=True)
    grab("description", "Description", required=True, multiline=True)
    grab("location", "Location", required=True)
    grab("distinguishing_features", "Distinguishing features", multiline=True)
    grab("private_contact", "Private contact")

    category = (form.get("category", "") or "").strip()
    if category not in categories:
        errors.append("Please choose a valid category.")
    cleaned["category"] = category

    try:
        cleaned["date_occurred"] = parse_date(form.get("date_occurred", ""), date_label)
    except ValidationError as exc:
        errors.extend(exc.errors)
        cleaned["date_occurred"] = (form.get("date_occurred", "") or "").strip()

    return cleaned, errors


# ---- Image upload content checks -------------------------------------------------
def sniff_image_type(head_bytes):
    """Return 'png' | 'jpg' | 'webp' based on file signature, else None."""
    if head_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head_bytes.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if len(head_bytes) >= 12 and head_bytes[:4] == b"RIFF" and head_bytes[8:12] == b"WEBP":
        return "webp"
    return None
