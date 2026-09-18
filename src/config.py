from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- Database ---
    DB_HOST: str
    DB_PORT: int
    DB_USER: str
    DB_PASS: str
    DB_NAME: str

    @property
    def DB_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASS}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

    # --- JWT ---
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int

    # --- Cookie ---
    COOKIE_NAME: str = "access_token"
    COOKIE_SECURE: bool = False          # True в проде (HTTPS)
    COOKIE_SAMESITE: str = "lax"         # "lax" | "strict" | "none"
    COOKIE_DOMAIN: str | None = None
    COOKIE_PATH: str = "/"

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()