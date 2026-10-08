import json
import os
import sqlite3
from functools import wraps

from flask import Flask, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "local-demo-key-change-before-hosting")
DB_PATH = os.environ.get("CAMPUSPULSE_DB", "campuspulse.db")


def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize_database():
    with connect_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('professor', 'hod', 'dean')),
                department TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                department TEXT NOT NULL,
                class_name TEXT NOT NULL,
                professor_id INTEGER NOT NULL REFERENCES users(id),
                attendance REAL NOT NULL CHECK(attendance BETWEEN 0 AND 100),
                marks REAL NOT NULL CHECK(marks BETWEEN 0 AND 100),
                assignments REAL NOT NULL CHECK(assignments BETWEEN 0 AND 100),
                quiz REAL NOT NULL CHECK(quiz BETWEEN 0 AND 100),
                subjects TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS interventions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL REFERENCES students(id),
                created_by INTEGER NOT NULL REFERENCES users(id),
                note TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)

        demo_users = [
            ("Aditi Rao", "prof@campuspulse.demo", "prof123", "professor", "CSE"),
            ("Rahul Verma", "itprof@campuspulse.demo", "itprof123", "professor", "IT"),
            ("Dr. Neha Shah", "hod@campuspulse.demo", "hod123", "hod", "CSE"),
            ("Dr. Aman Gill", "ithod@campuspulse.demo", "ithod123", "hod", "IT"),
            ("Dr. Meera Kapoor", "dean@campuspulse.demo", "dean123", "dean", "ALL"),
        ]
        for name, email, password, role, department in demo_users:
            db.execute("""INSERT OR IGNORE INTO users
                (name, email, password_hash, role, department) VALUES (?, ?, ?, ?, ?)""",
                (name, email, generate_password_hash(password), role, department))

        if db.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 0:
            professor_ids = {
                row["department"]: row["id"]
                for row in db.execute("SELECT id, department FROM users WHERE role='professor'")
            }
            samples = [
                ("Aarav Sharma", "aarav@example.demo", "CSE", "CSE Year 2", "CSE", 86, 78, 82, 74, {"Python": 84, "Maths": 73, "Networks": 78}),
                ("Meera Nair", "meera@example.demo", "CSE", "CSE Year 2", "CSE", 72, 64, 69, 61, {"Python": 70, "Maths": 58, "Networks": 64}),
                ("Kabir Khan", "kabir@example.demo", "CSE", "CSE Year 2", "CSE", 58, 49, 54, 43, {"Python": 52, "Maths": 41, "Networks": 47}),
                ("Ishita Rao", "ishita@example.demo", "CSE", "CSE Year 3", "CSE", 91, 88, 86, 90, {"AI": 91, "DBMS": 85, "Cloud": 88}),
                ("Anaya Verma", "anaya@example.demo", "IT", "IT Year 2", "IT", 81, 74, 78, 72, {"Web": 84, "Maths": 70, "Networks": 69}),
                ("Rehan Ali", "rehan@example.demo", "IT", "IT Year 2", "IT", 67, 59, 63, 55, {"Web": 61, "Maths": 52, "Networks": 64}),
                ("Tara Bose", "tara@example.demo", "IT", "IT Year 3", "IT", 94, 89, 92, 87, {"Cloud": 91, "Security": 86, "Web": 90}),
                ("Dev Patel", "dev@example.demo", "IT", "IT Year 3", "IT", 62, 57, 51, 60, {"Cloud": 59, "Security": 48, "Web": 63}),
            ]
            for name, email, dept, class_name, owner_dept, attendance, marks, assignments, quiz, subjects in samples:
                db.execute("""INSERT INTO students
                    (name, email, department, class_name, professor_id, attendance, marks, assignments, quiz, subjects)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (name, email, dept, class_name, professor_ids[owner_dept], attendance,
                     marks, assignments, quiz, json.dumps(subjects)))


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def visible_students(db):
    role = session["role"]
    if role == "dean":
        rows = db.execute("SELECT * FROM students ORDER BY department, class_name, name").fetchall()
    elif role == "hod":
        rows = db.execute("SELECT * FROM students WHERE department=? ORDER BY class_name, name",
                           (session["department"],)).fetchall()
    else:
        rows = db.execute("SELECT * FROM students WHERE professor_id=? ORDER BY class_name, name",
                           (session["user_id"],)).fetchall()
    return [enrich_student(row) for row in rows]


def enrich_student(row):
    student = dict(row)
    student["performance"] = round((student["attendance"] + student["marks"] +
                                    student["assignments"] + student["quiz"]) / 4, 1)
    student["risk"] = round(100 - student["performance"], 1)
    student["status"] = ("Priority support" if student["risk"] >= 50 else
                         "Check-in" if student["risk"] >= 30 else "On track")
    subjects = json.loads(student["subjects"] or "{}")
    student["subjects"] = subjects
    student["weak_subject"] = min(subjects, key=subjects.get) if subjects else "—"
    tips = []
    if student["attendance"] < 75:
        tips.append("Attend more classes and agree on a catch-up plan.")
    if student["marks"] < 60:
        tips.append("Review the lowest scoring topics with a short practice session.")
    if student["assignments"] < 60:
        tips.append("Break upcoming assignments into small weekly milestones.")
    if student["quiz"] < 60:
        tips.append("Try a short weekly quiz and review each missed question.")
    student["recommendation"] = tips[0] if tips else "Keep the current study routine and check progress next week."
    return student


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect_db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(user_id=user["id"], name=user["name"], role=user["role"],
                           department=user["department"])
            return redirect(url_for("dashboard"))
        error = "Email or password is incorrect. Use one of the demo accounts below."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_login
def dashboard():
    with connect_db() as db:
        students = visible_students(db)
        visible_ids = [student["id"] for student in students]
        if visible_ids:
            marks = ",".join("?" for _ in visible_ids)
            open_actions = db.execute(f"""SELECT i.*, s.name AS student_name FROM interventions i
                JOIN students s ON s.id=i.student_id
                WHERE i.status='Open' AND i.student_id IN ({marks})
                ORDER BY i.created_at DESC LIMIT 6""", visible_ids).fetchall()
        else:
            open_actions = []
    average = round(sum(s["performance"] for s in students) / len(students), 1) if students else 0
    attention = sum(s["status"] == "Priority support" for s in students)
    checkins = sum(s["status"] == "Check-in" for s in students)
    return render_template("dashboard.html", students=students, average=average,
                           attention=attention, checkins=checkins, open_actions=open_actions)


@app.route("/students/add", methods=["POST"])
@require_login
def add_student():
    if session["role"] == "professor":
        abort(403)
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    class_name = request.form.get("class_name", "").strip()
    department = session["department"] if session["role"] == "hod" else request.form.get("department", "").strip().upper()
    try:
        scores = [float(request.form.get(key, "")) for key in ("attendance", "marks", "assignments", "quiz")]
        if not name or not class_name or not email or not department:
            raise ValueError
        if any(score < 0 or score > 100 for score in scores):
            raise ValueError
        with connect_db() as db:
            professor = db.execute("SELECT id FROM users WHERE role='professor' AND department=? ORDER BY id LIMIT 1",
                                   (department,)).fetchone()
            if not professor:
                flash("No professor account exists for that department yet.", "error")
                return redirect(url_for("dashboard"))
            db.execute("""INSERT INTO students
                (name, email, department, class_name, professor_id, attendance, marks, assignments, quiz, subjects)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')""",
                (name, email, department, class_name, professor["id"], *scores))
        flash(f"Student {name} added.", "success")
    except sqlite3.IntegrityError:
        flash("That student email is already in the roster.", "error")
    except (ValueError, TypeError):
        flash("Enter all fields and scores from 0 to 100.", "error")
    return redirect(url_for("dashboard"))


@app.route("/interventions/add", methods=["POST"])
@require_login
def add_intervention():
    student_id = request.form.get("student_id", type=int)
    note = request.form.get("note", "").strip()
    if not student_id or not note:
        flash("Choose a student and enter a follow-up note.", "error")
        return redirect(url_for("dashboard"))
    with connect_db() as db:
        allowed_ids = {s["id"] for s in visible_students(db)}
        if student_id not in allowed_ids:
            abort(403)
        db.execute("INSERT INTO interventions (student_id, created_by, note) VALUES (?, ?, ?)",
                   (student_id, session["user_id"], note))
    flash("Support action added.", "success")
    return redirect(url_for("dashboard"))


@app.route("/interventions/<int:action_id>/close", methods=["POST"])
@require_login
def close_intervention(action_id):
    with connect_db() as db:
        allowed_ids = {s["id"] for s in visible_students(db)}
        action = db.execute("SELECT student_id FROM interventions WHERE id=?", (action_id,)).fetchone()
        if not action or action["student_id"] not in allowed_ids:
            abort(403)
        db.execute("UPDATE interventions SET status='Done' WHERE id=?", (action_id,))
    flash("Support action marked done.", "success")
    return redirect(url_for("dashboard"))


@app.errorhandler(403)
def forbidden(_error):
    return render_template("message.html", title="Access restricted",
                           message="Your account does not have permission to view or change this information."), 403


@app.route("/health")
def health():
    return {"status": "ok"}


initialize_database()

if __name__ == "__main__":
    app.run(debug=True)
