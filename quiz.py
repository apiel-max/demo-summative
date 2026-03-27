"""
quiz.py — Quiz Engine
Handles fetching questions, running quizzes, saving scores,
and retrieving score history and the leaderboard.
"""

import random
from datetime import datetime
from Database import get_connection

TOPICS = [
    "What is AI?",
    "AI Ethics & Responsibility",
    "AI in Everyday Life",
]


def fetch_questions(topic, limit=8):
    """Pull a random set of questions for the given topic from the database."""
    if topic not in TOPICS:
        print(f"\n  [ERROR] '{topic}' is not a valid topic.")
        return []

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM questions WHERE topic = ? ORDER BY RANDOM() LIMIT ?",
            (topic, limit)
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as error:
        print(f"\n  [ERROR] Could not load questions: {error}\n")
        return []
    finally:
        conn.close()


def shuffle_answer_options(question):
    """Randomly reshuffle the four answer options so positions change each attempt."""
    original_options = [
        ("A", question["option_a"]),
        ("B", question["option_b"]),
        ("C", question["option_c"]),
        ("D", question["option_d"]),
    ]
    correct_answer_text = dict(original_options)[question["correct_answer"].upper()]
    random.shuffle(original_options)

    shuffled_question = dict(question)
    new_correct_letter = "A"

    for index, (_, option_text) in enumerate(original_options):
        new_label = ["A", "B", "C", "D"][index]
        shuffled_question[f"option_{new_label.lower()}"] = option_text
        if option_text == correct_answer_text:
            new_correct_letter = new_label

    shuffled_question["correct_answer"] = new_correct_letter
    return shuffled_question, new_correct_letter


def run_quiz(user_id, topic):
    """Run a full quiz session and return the results dict, or {} on failure."""
    if not isinstance(user_id, int) or user_id <= 0:
        print("\n  [ERROR] Invalid user session. Please log in again.\n")
        return {}

    questions = fetch_questions(topic)
    if not questions:
        print(f"\n  No questions found for '{topic}'. Please try another topic.\n")
        return {}

    shuffled_questions = [shuffle_answer_options(q)[0] for q in questions]
    score = 0
    total_questions = len(shuffled_questions)
    review_log = []
    started_at = datetime.now()

    _print_quiz_header(topic, total_questions, started_at)

    for question_number, question in enumerate(shuffled_questions, start=1):
        try:
            print(f"\n  Q{question_number}. {question['question_text']}")
            print(f"       A)  {question['option_a']}")
            print(f"       B)  {question['option_b']}")
            print(f"       C)  {question['option_c']}")
            print(f"       D)  {question['option_d']}")
            print()

            player_answer = _get_valid_answer()
            correct_letter = question["correct_answer"].upper()
            is_correct = (player_answer == correct_letter)
            explanation = question.get("explanation", "No explanation available.")

            if is_correct:
                score += 1
                print("\n  Correct!")
            else:
                correct_option_text = {
                    "A": question["option_a"], "B": question["option_b"],
                    "C": question["option_c"], "D": question["option_d"],
                }.get(correct_letter, "")
                print(f"\n  Wrong! The correct answer was {correct_letter}) {correct_option_text}")

            print(f"  Reason: {explanation}")
            print("\n  " + "-" * 51)

            review_log.append({
                "question":       question["question_text"],
                "your_answer":    player_answer,
                "correct_answer": correct_letter,
                "is_correct":     is_correct,
                "explanation":    explanation,
            })

        except KeyboardInterrupt:
            print("\n\n  Quiz interrupted. Your progress will not be saved.\n")
            return {}
        except Exception as error:
            print(f"\n  [ERROR] Problem with question {question_number}: {error}. Skipping.\n")
            continue

    finished_at = datetime.now()
    percentage = round((score / total_questions) * 100, 1)

    _display_end_of_quiz(score, total_questions, percentage, started_at, finished_at)
    _save_score(user_id, topic, score, total_questions)

    return {
        "score":      score,
        "total":      total_questions,
        "percentage": percentage,
        "topic":      topic,
        "review":     review_log,
    }


def _save_score(user_id, topic, score, total):
    """Save the player's quiz result to the scores table."""
    if total == 0:
        return

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scores (user_id, topic, score, total) VALUES (?, ?, ?, ?)",
            (user_id, topic, score, total)
        )
        conn.commit()
    except Exception as error:
        print(f"  [ERROR] Could not save score: {error}")
    finally:
        conn.close()


def get_score_history(user_id):
    """Fetch all past quiz attempts for a user, newest first."""
    if not isinstance(user_id, int) or user_id <= 0:
        return []

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT topic, score, total, date_attempted
            FROM scores
            WHERE user_id = ?
            ORDER BY date_attempted DESC
            """,
            (user_id,)
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as error:
        print(f"  [ERROR] Could not fetch history: {error}")
        return []
    finally:
        conn.close()


def get_leaderboard(limit=10):
    """Fetch the top players ranked by their best quiz percentage."""
    if not isinstance(limit, int) or limit <= 0:
        limit = 10

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT u.username, u.age_group,
                   ROUND(MAX(CAST(s.score AS REAL) / s.total * 100), 1) AS best_pct,
                   COUNT(s.id) AS attempts,
                   MAX(s.date_attempted) AS last_attempted
            FROM scores s
            JOIN users u ON s.user_id = u.id
            GROUP BY u.username, u.age_group
            ORDER BY best_pct DESC
            LIMIT ?
            """,
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]
    except Exception as error:
        print(f"  [ERROR] Could not fetch leaderboard: {error}")
        return []
    finally:
        conn.close()


def _get_valid_answer():
    """Keep asking until the player enters A, B, C, or D."""
    while True:
        try:
            print("  Your answer:")
            print("    A")
            print("    B")
            print("    C")
            print("    D")
            player_input = input("  Enter choice: ").strip().upper()
            if player_input in ("A", "B", "C", "D"):
                return player_input
            print("  Please enter A, B, C, or D only.")
        except EOFError:
            return "A"


def _print_quiz_header(topic, total_questions, started_at):
    print("\n" + "=" * 55)
    print(f"  TOPIC: {topic.upper()}")
    print(f"  {total_questions} questions  |  Started: {started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)


def _display_end_of_quiz(score, total_questions, percentage, started_at, finished_at):
    duration = finished_at - started_at
    minutes, seconds = divmod(int(duration.total_seconds()), 60)

    print("\n" + "=" * 55)
    print("  QUIZ COMPLETE")
    print("=" * 55)
    print(f"  Your Score  :  {score} out of {total_questions}")
    print(f"  Percentage  :  {percentage}%")
    print(f"  Started     :  {started_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Finished    :  {finished_at.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Time Taken  :  {minutes}m {seconds}s")
    print("=" * 55 + "\n")
