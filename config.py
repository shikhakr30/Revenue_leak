import os
from urllib.parse import quote_plus

from dotenv import load_dotenv


load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-development-key")
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = 8 * 60 * 60

    ADMIN_NAME = os.getenv("ADMIN_NAME", "Portfolio Admin")
    ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@revenueleak.ai")
    ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@123")

    _db_user = os.getenv("DB_USER", "root")
    _db_password = quote_plus(os.getenv("DB_PASSWORD", ""))
    _db_host = os.getenv("DB_HOST", "127.0.0.1")
    _db_port = os.getenv("DB_PORT", "3306")
    _db_name = os.getenv("DB_NAME", "revenueleak_ai")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"mysql+pymysql://{_db_user}:{_db_password}@{_db_host}:{_db_port}/{_db_name}",
    )
