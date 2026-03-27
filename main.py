"""
main.py — Entry point for the AI Quiz App.
Wires together Database, Auth, and Quiz modules.
"""

from datetime import datetime
from Database import setup_database
from auth import register_user, login_user, VALID_AGE_GROUPS
from quiz import run_quiz, get_score_history, get_leaderboard, TOPICS


def main():
    print("\n  Connecting to database, please wait...")
    try:
        setup_database()
    except Exception as e:
        print(f"\n  [FATAL] Could not set up database: {e}\n")
        return

    print("\n" + "=" * 55)
    print("  Welcome to the AI Literacy Quiz App")
    print("=" * 55)

    while True:
        try:
            print("\n  " + "-" * 20)
            print("  1. Register")
            print("  2. Login")
            print("  3. Quit")
            print("  " + "-" * 20)
            choice = input("  Choose an option (1-3): ").strip()

            if choice == "1":
                handle_register()
            elif choice == "2":
                user_id, username = handle_login()
                if user_id:
                    user_menu(user_id, username)
            elif choice == "3":
                print("\n  Goodbye!\n")
                break
            else:
                print("  Please enter 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\n\n  Exiting. Goodbye!\n")
            break
        except Exception as e:
            print(f"\n  [ERROR] Unexpected error: {e}. Please try again.\n")


def handle_register():
    print("\n" + "=" * 55)
    print("  REGISTER")
    print("=" * 55)
    try:
        username = input("  Username      : ").strip()
        email    = input("  Email         : ").strip()
        password = input("  Password      : ").strip()
        print("  " + "-" * 53)
        print("  Age Group")
        print("  " + "-" * 53)
        print("  Please select the age group that applies to you.")
        print("  This allows the system to record your results")
        print("  accurately alongside learners in your age bracket.")
        print("  " + "-" * 53)
        for i, g in enumerate(VALID_AGE_GROUPS, 1):
            print(f"    {i}. {g}")
        print("  " + "-" * 20)
        age_choice = input("  Choose (1-4)  : ").strip()
        if age_choice in ("1", "2", "3", "4"):
            age_group = VALID_AGE_GROUPS[int(age_choice) - 1]
            success, message = register_user(username, email, password, age_group)
            print(f"\n  {message}")
        else:
            print("  Invalid choice. Please enter 1, 2, 3, or 4.")
    except KeyboardInterrupt:
        print("\n  Registration cancelled.")
    except Exception as e:
        print(f"\n  [ERROR] Registration error: {e}")


def handle_login():
    print("\n" + "=" * 55)
    print("  LOGIN")
    print("=" * 55)
    try:
        username = input("  Username: ").strip()
        password = input("  Password: ").strip()
        success, message, user_id = login_user(username, password)
        print(f"\n  {message}")
        return (user_id, username) if success else (None, None)
    except KeyboardInterrupt:
        print("\n  Login cancelled.")
        return None, None
    except Exception as e:
        print(f"\n  [ERROR] Login error: {e}")
        return None, None


def user_menu(user_id: int, username: str):
    while True:
        try:
            print("\n" + "=" * 55)
            print(f"  MENU  —  {username}")
            print("=" * 55)
            print("  1. Take a Quiz")
            print("  2. View My Score History")
            print("  3. View Leaderboard")
            print("  4. Logout")
            print("  " + "-" * 20)
            choice = input("  Choose an option (1-4): ").strip()

            if choice == "1":
                print("\n  Topics:")
                for i, t in enumerate(TOPICS, 1):
                    print(f"    {i}. {t}")
                t_choice = input("  Select topic (1-3): ").strip()
                if t_choice in ("1", "2", "3"):
                    run_quiz(user_id, TOPICS[int(t_choice) - 1])
                else:
                    print("  Invalid choice. Please enter 1, 2, or 3.")

            elif choice == "2":
                try:
                    history = get_score_history(user_id)
                    if not history:
                        print("\n  No quiz history yet.")
                    else:
                        print("\n" + "=" * 55)
                        print("  YOUR HISTORY")
                        print("=" * 55)
                        for row in history:
                            pct = round(row["score"] / row["total"] * 100, 1)
                            ts = row["date_attempted"][:19] if row["date_attempted"] else "N/A"
                            print(f"  {ts}  |  {row['topic']}  |  {row['score']}/{row['total']}  ({pct}%)")
                except Exception as e:
                    print(f"\n  [ERROR] Could not load history: {e}")

            elif choice == "3":
                try:
                    board = get_leaderboard()
                    if not board:
                        print("\n  No leaderboard data yet.")
                    else:
                        print("\n" + "=" * 75)
                        print("  LEADERBOARD")
                        print("=" * 75)
                        print(f"  {'S/N':<5} {'Name':<30} {'Age Group':<12} {'Best Score':<12} {'Attempts':<10} {'Last Attempt'}")
                        print("  " + "-" * 73)
                        for i, row in enumerate(board, 1):
                            ts = row["last_attempted"][:16] if row["last_attempted"] else "N/A"
                            name     = row['username'][:28]
                            age      = row['age_group']
                            best     = str(row['best_pct']) + "%"
                            attempts = str(row['attempts'])
                            print(f"  {str(i):<5} {name:<30} {age:<12} {best:<12} {attempts:<10} {ts}")
                        print("  " + "-" * 73)
                except Exception as e:
                    print(f"\n  [ERROR] Could not load leaderboard: {e}")

            elif choice == "4":
                print(f"\n  Logged out. Goodbye, {username}!")
                break
            else:
                print("  Please enter 1, 2, 3, or 4.")

        except KeyboardInterrupt:
            print(f"\n  Session ended. Goodbye, {username}!\n")
            break
        except Exception as e:
            print(f"\n  [ERROR] Unexpected error: {e}. Please try again.\n")


if __name__ == "__main__":
    main()