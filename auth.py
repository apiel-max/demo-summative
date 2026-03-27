"""
auth.py — User Authentication
Handles user registration and login using the local SQLite database.
"""

import hashlib
from Database import get_connection

VALID_AGE_GROUPS = ["Under 13", "13-17", "18-25", "26+"]


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def register_user(username: str, password: str, age_group: str, email: str = None):
    """
    Register a new user.
    Returns (True, success_message) or (False, error_message).
    """
    if not username or not password or not age_group:
        return False, "Username, password, and age group are required."

    if len(password) < 6:
        return False, "Password must be at least 6 characters."

    if age_group not in VALID_AGE_GROUPS:
        return False, f"Invalid age group. Choose from: {', '.join(VALID_AGE_GROUPS)}"

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password, age_group) VALUES (?, ?, ?, ?)",
            (username, email, _hash_password(password), age_group)
        )
        conn.commit()
        return True, f"Account created successfully! Welcome, {username}."
    except Exception as e:
        if "UNIQUE" in str(e):
            return False, "That username or email is already taken."
        return False, f"Registration failed: {e}"
    finally:
        conn.close()


def login_user(username: str, password: str):
    """
    Verify credentials.
    Returns (True, message, user_id) on success or (False, message, None) on failure.
    """
    if not username or not password:
        return False, "Username and password are required.", None

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, password FROM users WHERE username = ?",
            (username,)
        )
        row = cursor.fetchone()

        if not row:
            return False, "Username not found.", None

        if row["password"] != _hash_password(password):
            return False, "Incorrect password.", None

        return True, f"Welcome back, {username}!", row["id"]
    except Exception as e:
        return False, f"Login failed: {e}", None
    finally:
        conn.close()
