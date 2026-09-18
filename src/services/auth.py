from datetime import datetime, timezone, timedelta

import jwt
from fastapi import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from src.config import settings


class AuthService:
    """JWT + хеширование паролей.

    Хеширование — Werkzeug PBKDF2-SHA256, формат:
        pbkdf2:sha256:100000$<salt>$<hex_digest>
    Длина ~102 символа -> в БД колонка hashed_password минимум VARCHAR(255).
    """

    # --- JWT ---

    def create_access_token(self, data: dict) -> str:
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
        to_encode |= {"exp": expire}
        return jwt.encode(
            to_encode,
            settings.JWT_SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM,
        )

    def encode_token(self, token: str) -> dict:
        """Прочитать JWT. Имя оставлено для совместимости с dependencies.py.

        Бросает HTTPException 401, если токен невалиден/истёк.
        """
        try:
            return jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
        except jwt.exceptions.PyJWTError:
            raise HTTPException(status_code=401, detail="Неверный токен")

    # --- Пароли ---

    def hash_password(self, password: str) -> str:
        return generate_password_hash(password, method="pbkdf2:sha256:100000")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        if not hashed_password:
            return False

        hashed_password = hashed_password.strip().strip('"').strip("'")

        # Werkzeug PBKDF2
        if hashed_password.startswith("pbkdf2:") or hashed_password.startswith("$pbkdf2"):
            try:
                return check_password_hash(hashed_password, plain_password)
            except ValueError:
                return False

        # Старые bcrypt-хеши (если в БД остались) — только если установлен bcrypt
        if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
            try:
                import bcrypt

                pwd = plain_password.encode("utf-8")[:72]
                return bcrypt.checkpw(pwd, hashed_password.encode("utf-8"))
            except (ValueError, ImportError):
                return False

        return False