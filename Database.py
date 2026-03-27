"""
Database.py — Backend & Database
Uses a local SQLite database file (quiz_app.db).
Handles table creation and question seeding.
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "quiz_app.db")


def get_connection():
    """Return a live SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # allows dict-style access: row["column"]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def setup_database():
    """Create all required tables if they don't exist, then seed questions."""
    try:
        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                email       TEXT UNIQUE,
                password    TEXT NOT NULL,
                age_group   TEXT NOT NULL,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                topic           TEXT NOT NULL,
                question_text   TEXT NOT NULL,
                option_a        TEXT NOT NULL,
                option_b        TEXT NOT NULL,
                option_c        TEXT NOT NULL,
                option_d        TEXT NOT NULL,
                correct_answer  TEXT NOT NULL,
                explanation     TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scores (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER NOT NULL,
                topic           TEXT NOT NULL,
                score           INTEGER NOT NULL,
                total           INTEGER NOT NULL,
                date_attempted  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)

        conn.commit()
        _seed_questions(cursor, conn)
        conn.close()
        return True

    except Exception as e:
        print(f"\n  [ERROR] Could not set up database: {e}\n")
        return False


def _seed_questions(cursor, conn):
    """Insert quiz questions only if the table is empty."""
    cursor.execute("SELECT COUNT(*) FROM questions")
    count = cursor.fetchone()[0]
    if count > 0:
        return

    questions = [
        # ── Topic 1: What is AI? ──────────────────────────────────────────────
        ("What is AI?",
         "What does AI stand for?",
         "Automated Interface", "Artificial Intelligence",
         "Automated Intelligence", "Artificial Interface",
         "B",
         "AI stands for Artificial Intelligence — the ability of a machine to mimic human thinking."),

        ("What is AI?",
         "Which of the following best describes Artificial Intelligence?",
         "A robot that can walk",
         "A machine that can perform tasks that normally require human intelligence",
         "A computer with a large hard drive",
         "Software that only follows fixed instructions",
         "B",
         "AI refers to systems that simulate human-like reasoning, learning, and decision-making."),

        ("What is AI?",
         "What is machine learning?",
         "Programming a computer with fixed rules",
         "Teaching a computer using examples and data so it learns on its own",
         "Installing software on a computer",
         "Connecting computers to the internet",
         "B",
         "Machine learning allows computers to learn patterns from data without being explicitly programmed."),

        ("What is AI?",
         "Which of the following is an example of AI in action?",
         "A calculator adding two numbers",
         "A word processor checking spelling",
         "A music app recommending songs based on your listening history",
         "A printer printing a document",
         "C",
         "Recommendation systems (like Spotify or YouTube) use AI to predict what you'll enjoy next."),

        ("What is AI?",
         "What is a neural network modelled after?",
         "Computer circuits", "The human brain",
         "Database tables", "Mathematical equations",
         "B",
         "Neural networks are inspired by how neurons in the human brain connect and communicate."),

        ("What is AI?",
         "What does 'training' an AI model mean?",
         "Installing the AI on a computer",
         "Giving the AI physical exercise",
         "Feeding the AI large amounts of data so it can learn patterns",
         "Writing code line by line for every possible situation",
         "C",
         "Training means exposing a model to data so it adjusts its internal parameters to improve accuracy."),

        ("What is AI?",
         "Which field is NOT a branch of Artificial Intelligence?",
         "Natural Language Processing",
         "Computer Vision",
         "Civil Engineering",
         "Machine Learning",
         "C",
         "Civil engineering is a physical infrastructure discipline, not a branch of AI."),

        ("What is AI?",
         "What is the purpose of a training dataset?",
         "To test the model after deployment",
         "To teach the model by exposing it to examples",
         "To store the final AI application",
         "To design the user interface",
         "B",
         "Training data provides the examples an AI model learns from to develop its capabilities."),

        # ── Topic 2: AI Ethics & Responsibility ───────────────────────────────
        ("AI Ethics & Responsibility",
         "What does it mean to use AI ethically?",
         "Using AI only for entertainment",
         "Using AI in ways that are fair, honest, and do not harm others",
         "Using AI without reading the terms of service",
         "Using AI to complete all schoolwork without learning",
         "B",
         "Ethical AI use means being fair, transparent, and avoiding harm to individuals or communities."),

        ("AI Ethics & Responsibility",
         "Why is it considered unethical to submit AI-generated work as your own school assignment?",
         "Because AI tools cost money",
         "Because the teacher will not understand it",
         "Because it is dishonest and prevents you from developing your own skills",
         "Because AI always makes mistakes",
         "C",
         "Academic integrity requires that submitted work reflects your own learning and effort."),

        ("AI Ethics & Responsibility",
         "What is AI bias?",
         "When AI systems run too slowly",
         "When AI produces unfair or prejudiced results due to imbalanced training data",
         "When AI refuses to answer a question",
         "When AI is used for gaming",
         "B",
         "AI bias occurs when training data reflects historical prejudices, causing the model to produce unfair outcomes."),

        ("AI Ethics & Responsibility",
         "Which of the following is a responsible way to use AI at school?",
         "Using AI to generate answers and copying them directly",
         "Using AI to help you understand a concept, then writing in your own words",
         "Sharing your classmate's account to access AI tools",
         "Using AI to impersonate a teacher",
         "B",
         "Responsible use means using AI as a learning aid — to understand, not to replace your own thinking."),

        ("AI Ethics & Responsibility",
         "What is data privacy in the context of AI?",
         "Keeping your Wi-Fi password secret",
         "The right of individuals to control how their personal data is collected and used by AI systems",
         "Deleting files from your computer",
         "Making AI systems run faster",
         "B",
         "Data privacy ensures that AI systems collect and use personal information only with proper consent and protection."),

        ("AI Ethics & Responsibility",
         "A company uses an AI hiring tool that consistently rejects applications from women. This is an example of:",
         "Efficient automation",
         "AI creativity",
         "Algorithmic bias causing discrimination",
         "Proper use of AI",
         "C",
         "When AI perpetuates gender or racial discrimination, it is a serious ethical failure that must be corrected."),

        ("AI Ethics & Responsibility",
         "What should you do if you are unsure whether an AI-generated fact is true?",
         "Share it immediately on social media",
         "Assume it is correct because AI is always right",
         "Verify it using reliable sources before using or sharing it",
         "Ignore it",
         "C",
         "AI can generate plausible-sounding but incorrect information (hallucinations). Always fact-check."),

        ("AI Ethics & Responsibility",
         "Which UNESCO value is central to responsible AI development?",
         "Speed and efficiency above all",
         "Profit maximisation",
         "Human dignity, rights, and inclusion",
         "Replacing all human workers",
         "C",
         "UNESCO's AI ethics recommendation places human dignity, rights, and social inclusion at the core of AI governance."),

        # ── Topic 3: AI in Everyday Life ──────────────────────────────────────
        ("AI in Everyday Life",
         "Which of the following everyday tools uses AI?",
         "A standard wall clock",
         "A voice assistant like Siri or Google Assistant",
         "A traditional paper map",
         "A manual typewriter",
         "B",
         "Voice assistants use natural language processing (NLP) and AI to understand and respond to your speech."),

        ("AI in Everyday Life",
         "How does a spam filter in your email use AI?",
         "It deletes all emails automatically",
         "It learns patterns of spam messages and blocks similar ones",
         "It reads your emails out loud",
         "It sends automatic replies",
         "B",
         "Spam filters use machine learning to detect patterns in unwanted emails and filter them out."),

        ("AI in Everyday Life",
         "What AI feature does a smartphone camera use when it detects and frames faces?",
         "Bluetooth technology",
         "Facial recognition powered by computer vision",
         "Standard optical zoom",
         "GPS tracking",
         "B",
         "Smartphone cameras use computer vision — a branch of AI — to detect, recognize, and frame faces."),

        ("AI in Everyday Life",
         "Netflix recommending a movie you might like is an example of:",
         "Random selection",
         "A recommendation system powered by AI",
         "Manual curation by Netflix staff",
         "Alphabetical sorting",
         "B",
         "Recommendation engines analyse your viewing history using AI to predict content you will enjoy."),

        ("AI in Everyday Life",
         "How is AI used in healthcare?",
         "AI replaces all doctors permanently",
         "AI helps doctors detect diseases earlier by analysing medical scans and patient data",
         "AI only manages hospital billing",
         "AI has no role in healthcare",
         "B",
         "AI assists medical professionals by analysing X-rays, MRIs, and patient data to improve diagnosis accuracy."),

        ("AI in Everyday Life",
         "What does a navigation app like Google Maps use AI for?",
         "To display a static road map",
         "To predict real-time traffic and suggest the fastest route",
         "To track your calls",
         "To store your contacts",
         "B",
         "Google Maps uses AI to analyse live traffic data and dynamically recalculate the best route."),

        ("AI in Everyday Life",
         "Which of the following is a potential negative effect of AI in everyday life?",
         "Faster internet speeds",
         "Job displacement when AI automates tasks previously done by humans",
         "Cheaper smartphones",
         "Larger storage capacity",
         "B",
         "Automation powered by AI can eliminate certain jobs, requiring workers to adapt and reskill."),

        ("AI in Everyday Life",
         "A student uses an AI chatbot to get a summary of a history topic before studying further. This is:",
         "Cheating, because AI should never be used for school",
         "A responsible use of AI as a starting point for learning",
         "Pointless, because AI knows nothing about history",
         "Illegal in all schools",
         "B",
         "Using AI to get an overview before studying deeper is a smart, responsible learning strategy."),
    ]

    cursor.executemany("""
        INSERT INTO questions
            (topic, question_text, option_a, option_b, option_c, option_d, correct_answer, explanation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, questions)
    conn.commit()


if __name__ == "__main__":
    if setup_database():
        print("Database connected and tables ready!")
    else:
        print("Setup aborted — fix the error above.")
