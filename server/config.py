import os
from dotenv import load_dotenv

# Locate the root directory of the project
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(ROOT_DIR, ".env")
load_dotenv(dotenv_path=env_path)

HOST = os.getenv("STS_HOST", "0.0.0.0")
PORT = int(os.getenv("STS_PORT", "6000"))

def make_abs(path):
    """Converts a relative path to absolute, relative to the project root."""
    if not path:
        return path
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(ROOT_DIR, path))

# Resolve database directories and files
DB_DIR_raw = os.getenv("DB_DIR", "server/data")
DB_DIR = make_abs(DB_DIR_raw)

if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR, exist_ok=True)

CA_CERT = make_abs(os.getenv("CA_CERT_PATH", os.path.join(DB_DIR_raw, "rootCA.pem")))
CA_KEY = make_abs(os.getenv("CA_KEY_PATH", os.path.join(DB_DIR_raw, "rootCA.key")))
USER_DB = make_abs(os.getenv("USER_DB_PATH", os.path.join(DB_DIR_raw, "users.json")))
BANNED_DB = make_abs(os.getenv("BANNED_DB_PATH", os.path.join(DB_DIR_raw, "banned.json")))
CERT_DB = make_abs(os.getenv("CERT_DB_PATH", os.path.join(DB_DIR_raw, "cert_db.json")))
CRL_DB = make_abs(os.getenv("CRL_DB_PATH", os.path.join(DB_DIR_raw, "revoked_serials.json")))

# Default admin master password check params (Default: "admin" with "default_salt_for_development")
MASTER_PASSWORD_HASH = os.getenv("MASTER_PASSWORD_HASH", "6c537790c2fc1990f71039615ca9f34a9862f73838ec342929da92984b07f436")
MASTER_PASSWORD_SALT = os.getenv("MASTER_PASSWORD_SALT", "default_salt_for_development")

# Logging configurations
import logging
LOG_FILE = make_abs(os.getenv("STS_LOG_FILE", "server/data/sts.log"))
LOG_LEVEL = getattr(logging, os.getenv("STS_LOG_LEVEL", "INFO").upper(), logging.INFO)

