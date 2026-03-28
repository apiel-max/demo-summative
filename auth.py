"""
auth.py — User Authentication
Handles user registration and login using the local SQLite database.
"""

import hashlib
from Database import get_connection

VALID_AGE_GROUPS = ["Under 13", "13-17", "18-25", "26+"]
AGE_MAP = {str(i+1): age for i, age in enumerate(VALID_AGE_GROUPS)}


def _hash_password(password: str) -> str:
    """Return SHA-256 hash of the password."""
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


# -----------------------
# CLI helper functions
# -----------------------
def cli_register():
    """Run a command-line registration prompt."""
    print("\n=== REGISTER NEW USER ===\n")
    username = input("Enter username: ").strip()
    password = input("Enter password (min 6 chars): ").strip()
    email = input("Enter email (optional): ").strip() or None

    # Show age group choices
    print("\nSelect age group:")
    for key, val in AGE_MAP.items():
        print(f"{key}. {val}")
    choice = input("Choose (1-4): ").strip()

    age_group = AGE_MAP.get(choice)
    if not age_group:
        print("Invalid choice. Registration cancelled.")
        return

    success, msg = register_user(username, password, age_group, email)
    print(msg)


def cli_login():
    """Run a command-line login prompt."""
    print("\n=== USER LOGIN ===\n")
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    success, msg, user_id = login_user(username, password)
    print(msg)
    return user_id if success else None


# -----------------------
# Optional: test flow
# -----------------------
if __name__ == "__main__":
    print("Welcome! Choose an option:")
    print("1. Register")
    print("2. Login")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        cli_register()
    elif choice == "2":
        cli_login()
    else:
        print("Invalid option.")
