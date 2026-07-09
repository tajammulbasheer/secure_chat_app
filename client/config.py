import os
from dotenv import load_dotenv

# Locate the root directory of the project
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(ROOT_DIR, ".env")
load_dotenv(dotenv_path=env_path)

KDC_IP = os.getenv("KDC_IP", "127.0.0.1")
KDC_PORT = int(os.getenv("KDC_PORT", "6000"))
PEER_PORT = int(os.getenv("PEER_PORT", "7000"))
CA_CERT_PATH = os.getenv("CA_CERT_PATH") # Optional override

# Logging configurations
import logging
LOG_LEVEL = getattr(logging, os.getenv("CLIENT_LOG_LEVEL", "INFO").upper(), logging.INFO)

