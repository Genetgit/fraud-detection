import re
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from email_validator import validate_email, EmailNotValidError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = "CHANGE_THIS_TO_A_RANDOM_SECRET_IN_PRODUCTION"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

ALLOWED_STAFF_DOMAIN = "@cbe.com.et"


def is_valid_staff_email(email: str) -> bool:
    """የባንኩ ኢሜይል (@cbe.com.et) ብቻ መሆኑን ያረጋግጣል።"""
    return email.lower().endswith(ALLOWED_STAFF_DOMAIN)


def is_real_email_domain(email: str) -> bool:
    """የኢሜይሉ ዶሜይን በኢንተርኔት ላይ መኖሩን (MX record) ያረጋግጣል።"""
    try:
        validate_email(email, check_deliverability=True)
        return True
    except EmailNotValidError:
        return False


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


def is_strong_password(password: str) -> bool:
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True


def create_access_token(user_id: int, role: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "role": role, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def is_locked(user) -> bool:
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
    return False


def register_failed_attempt(user, db):
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_login_attempts = 0
    db.commit()


def reset_failed_attempts(user, db):
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()
