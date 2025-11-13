# ============================================================
# Shared Helper Functions (ASCII-only)
# ============================================================

import re
import os
import json
from pathlib import Path


# ------------------------------------------------------------
# Extract Google Sheet or Drive ID from share links
# ------------------------------------------------------------
def extract_google_id(url_or_id):
    """
    Extracts a Google file ID from a shared URL, or returns it unchanged
    if the input is already an ID.

    Example:
        https://docs.google.com/spreadsheets/d/1abcDEFghiJKL12345/edit#gid=0
        -> 1abcDEFghiJKL12345
    """
    if not url_or_id:
        return ""
    match = re.search(r"/d/([A-Za-z0-9_-]+)", url_or_id)
    if match:
        return match.group(1)
    return url_or_id.strip()


# ------------------------------------------------------------
# Ensure that a local folder exists
# ------------------------------------------------------------
def ensure_folder(path):
    """Create a folder if it does not exist, and return its Path object."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


# ------------------------------------------------------------
# Load and save small JSON settings files
# ------------------------------------------------------------
def load_json(path):
    """Safely load a JSON file and return a dictionary."""
    p = Path(path)
    if not p.exists():
        return {}
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_json(path, data):
    """Safely write a dictionary to a JSON file."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print("Error saving JSON:", e)


# ------------------------------------------------------------
# Get a platform-safe user documents folder
# ------------------------------------------------------------
def get_documents_folder():
    """Return the user's Documents folder path."""
    if os.name == "nt":
        return Path(os.path.expanduser("~")) / "Documents"
    else:
        return Path.home() / "Documents"
