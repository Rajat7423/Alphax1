import csv
import io
import json
import os
import secrets
import sqlite3
from datetime import date
from functools import wraps

from flask import Flask, abort, flash, make_response, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") == "true",
)
DB_PATH = os.environ.get("CAMPUSPULSE_DB", "campuspulse.db")
ROLES = {"dean", "hod", "professor", "lab_assistant"}
STAFF_ROLES = {"dean", "hod", "professor"}


@app.before_request
def verify_post_token():
    if request.method == "POST":
        expected = session.get("_csrf_token", "")
        received = request.form.get("_csrf_token", "")
        if not expected or not secrets.compare_digest(expected, received):
            abort(400)


@app.context_processor
def inject_security_values():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return {"csrf_token": token}


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def initialize_database():
    with connect_db() as db:
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version < 3 and db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone():
            # Version 1 contained only seeded demo accounts and sample students.
            db.executescript("DROP TABLE IF EXISTS interventions; DROP TABLE IF EXISTS students; DROP TABLE IF EXISTS users;")
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('professor','hod','dean','lab_assistant')),
                department TEXT NOT NULL DEFAULT 'ALL',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                department TEXT NOT NULL,
                class_name TEXT NOT NULL,
                professor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                attendance REAL NOT NULL DEFAULT 0 CHECK(attendance BETWEEN 0 AND 100),
                marks REAL NOT NULL DEFAULT 0 CHECK(marks BETWEEN 0 AND 100),
                assignments REAL NOT NULL DEFAULT 0 CHECK(assignments BETWEEN 0 AND 100),
                quiz REAL NOT NULL DEFAULT 0 CHECK(quiz BETWEEN 0 AND 100),
                subjects TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS interventions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                created_by INTEGER NOT NULL REFERENCES users(id),
                note TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS attendance_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
                attendance_date TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('Present','Absent')),
                recorded_by INTEGER NOT NULL REFERENCES users(id),
                UNIQUE(student_id, attendance_date)
            );
            CREATE TABLE IF NOT EXISTS announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                department TEXT NOT NULL DEFAULT 'ALL',
                created_by INTEGER NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS lab_equipment (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                lab_name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Available',
                notes TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS lab_bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                equipment_id INTEGER NOT NULL REFERENCES lab_equipment(id),
                booked_by INTEGER NOT NULL REFERENCES users(id),
                booking_date TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                purpose TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Requested',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_students_department ON students(department, class_name);
            CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance_records(attendance_date);
            CREATE INDEX IF NOT EXISTS idx_announcements_department ON announcements(department, created_at);
        """)
        if version < 3:
            db.execute("PRAGMA user_version = 3")
def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "role" not in session:
            return redirect(url_for("login"))
        with connect_db() as db:
            if session["role"] == "student":
                active = db.execute("SELECT is_active FROM students WHERE id=?", (session.get("student_id"),)).fetchone()
            else:
                active = db.execute("SELECT is_active FROM users WHERE id=?", (session.get("user_id"),)).fetchone()
        if not active or not active["is_active"]:
            session.clear()
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def require_roles(*roles):
    def decorator(view):
        @wraps(view)
        @require_login
        def wrapped(*args, **kwargs):
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def visible_students(db):
    role = session["role"]
    if role == "student":
        rows = db.execute("SELECT * FROM students WHERE id=?", (session["student_id"],)).fetchall()
    elif role == "dean":
        rows = db.execute("SELECT * FROM students ORDER BY department,class_name,name").fetchall()
    elif role == "hod":
        rows = db.execute("SELECT * FROM students WHERE department=? ORDER BY class_name,name", (session["department"],)).fetchall()
    elif role == "professor":
        rows = db.execute("SELECT * FROM students WHERE professor_id=? ORDER BY class_name,name", (session["user_id"],)).fetchall()
    else:
        rows = []
    return [enrich_student(row) for row in rows]


def enrich_student(row):
    student = dict(row)
    student.pop("password_hash", None)
    student["performance"] = round((student["attendance"] + student["marks"] + student["assignments"] + student["quiz"]) / 4, 1)
    student["risk"] = round(100 - student["performance"], 1)
    student["status"] = "Priority support" if student["risk"] >= 50 else "Check-in" if student["risk"] >= 30 else "On track"
    subjects = json.loads(student["subjects"] or "{}")
    student["weak_subject"] = min(subjects, key=subjects.get) if subjects else "—"
    tips = []
    if student["attendance"] < 75: tips.append("Agree on a class catch-up plan.")
    if student["marks"] < 60: tips.append("Review low-scoring topics together.")
    if student["assignments"] < 60: tips.append("Set small weekly assignment milestones.")
    if student["quiz"] < 60: tips.append("Review missed questions in a short weekly session.")
    student["recommendation"] = tips[0] if tips else "Keep the current routine and review progress next week."
    return student


def account_count(db):
    return db.execute("SELECT (SELECT COUNT(*) FROM users)+(SELECT COUNT(*) FROM students)").fetchone()[0]


@app.route("/setup", methods=["GET", "POST"])
def setup():
    with connect_db() as db:
        if account_count(db):
            return redirect(url_for("login"))
    setup_key = os.environ.get("INITIAL_DEAN_KEY", "")
    error = ""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        submitted_key = request.form.get("setup_key", "")
        if not setup_key or not secrets.compare_digest(setup_key, submitted_key):
            error = "Setup key is incorrect. Ask the person who configured the college workspace."
        elif len(name) < 2 or "@" not in email or len(password) < 10:
            error = "Enter your name and email, and use a password with at least 10 characters."
        else:
            with connect_db() as db:
                if account_count(db):
                    return redirect(url_for("login"))
                db.execute("INSERT INTO users(name,email,password_hash,role,department) VALUES(?,?,?,?,?)",
                           (name, email, generate_password_hash(password), "dean", "ALL"))
            flash("Dean account created. Sign in to set up your college workspace.", "success")
            return redirect(url_for("login"))
    return render_template("setup.html", error=error, setup_enabled=bool(setup_key))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    with connect_db() as db:
        needs_setup = account_count(db) == 0
    if needs_setup:
        return redirect(url_for("setup"))
    if request.method == "POST":
        role = request.form.get("role", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect_db() as db:
            if role == "student":
                account = db.execute("SELECT id,name,email,password_hash,department FROM students WHERE email=? COLLATE NOCASE AND is_active=1", (email,)).fetchone()
            elif role in ROLES:
                account = db.execute("SELECT id,name,email,password_hash,role,department FROM users WHERE email=? COLLATE NOCASE AND role=? AND is_active=1", (email, role)).fetchone()
            else:
                account = None
        if account and check_password_hash(account["password_hash"], password):
            session.clear()
            session.update(name=account["name"], email=account["email"], role=role, department=account["department"])
            if role == "student":
                session.update(user_id=0, student_id=account["id"])
            else:
                session.update(user_id=account["id"])
            return redirect(url_for("dashboard"))
        error = "Email, password, or selected role is incorrect."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@require_login
def dashboard():
    with connect_db() as db:
        students = visible_students(db)
        visible_ids = [s["id"] for s in students]
        actions = []
        if visible_ids and session["role"] in STAFF_ROLES:
            marks = ",".join("?" for _ in visible_ids)
            actions = db.execute(f"""SELECT i.*,s.name AS student_name FROM interventions i
                JOIN students s ON s.id=i.student_id WHERE i.status='Open' AND i.student_id IN ({marks})
                ORDER BY i.created_at DESC LIMIT 8""", visible_ids).fetchall()
        if session["role"] in {"dean", "student"}:
            announcements = db.execute("SELECT * FROM announcements WHERE department IN ('ALL',?) ORDER BY created_at DESC LIMIT 8", (session["department"],)).fetchall()
        else:
            announcements = db.execute("SELECT * FROM announcements WHERE department IN ('ALL',?) ORDER BY created_at DESC LIMIT 8", (session["department"],)).fetchall()
        equipment = db.execute("SELECT * FROM lab_equipment ORDER BY lab_name,name").fetchall()
        if session["role"] == "dean":
            accounts = db.execute("SELECT id,name,email,role,department,is_active FROM users ORDER BY role,department,name").fetchall()
            professor_options = db.execute("SELECT id,name,department FROM users WHERE role='professor' AND is_active=1 ORDER BY department,name").fetchall()
            student_accounts = db.execute("SELECT id,name,email,department,class_name,is_active FROM students ORDER BY department,class_name,name").fetchall()
            departments = [r[0] for r in db.execute("SELECT department FROM users WHERE role!='dean' UNION SELECT department FROM students ORDER BY department").fetchall()]
        elif session["role"] == "hod":
            accounts = []
            professor_options = db.execute("SELECT id,name,department FROM users WHERE role='professor' AND department=? AND is_active=1 ORDER BY name", (session["department"],)).fetchall()
            student_accounts = db.execute("SELECT id,name,email,department,class_name,is_active FROM students WHERE department=? ORDER BY class_name,name", (session["department"],)).fetchall()
            departments = [session["department"]]
        else:
            accounts = []
            professor_options = []
            student_accounts = []
            departments = [session["department"]]
        if session["role"] in {"lab_assistant", "dean"}:
            bookings = db.execute("SELECT b.*,e.name AS equipment_name,e.lab_name,u.name AS booked_by_name FROM lab_bookings b JOIN lab_equipment e ON e.id=b.equipment_id JOIN users u ON u.id=b.booked_by ORDER BY b.booking_date DESC,b.start_time LIMIT 12").fetchall()
        elif session["role"] == "professor":
            bookings = db.execute("SELECT b.*,e.name AS equipment_name,e.lab_name,u.name AS booked_by_name FROM lab_bookings b JOIN lab_equipment e ON e.id=b.equipment_id JOIN users u ON u.id=b.booked_by WHERE b.booked_by=? ORDER BY b.booking_date DESC,b.start_time LIMIT 12", (session["user_id"],)).fetchall()
        else:
            bookings = []
    average = round(sum(s["performance"] for s in students) / len(students), 1) if students else 0
    attention = sum(s["status"] == "Priority support" for s in students)
    checkins = sum(s["status"] == "Check-in" for s in students)
    return render_template("dashboard.html", students=students, average=average, attention=attention,
                           checkins=checkins, open_actions=actions, announcements=announcements,
                           equipment=equipment, bookings=bookings, today=date.today().isoformat(),
                           accounts=accounts, student_accounts=student_accounts,
                           professor_options=professor_options, departments=departments)


@app.route("/users/add", methods=["POST"])
@require_roles("dean")
def add_user():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()
    department = request.form.get("department", "").strip().upper()
    if role not in {"dean", "hod", "professor", "lab_assistant"} or len(name) < 2 or "@" not in email or len(password) < 10 or not department:
        flash("Fill every field and choose a password of at least 10 characters.", "error")
        return redirect(url_for("dashboard"))
    try:
        with connect_db() as db:
            if db.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE UNION SELECT 1 FROM students WHERE email=? COLLATE NOCASE", (email, email)).fetchone():
                flash("That email is already in use.", "error")
                return redirect(url_for("dashboard"))
            db.execute("INSERT INTO users(name,email,password_hash,role,department) VALUES(?,?,?,?,?)",
                       (name, email, generate_password_hash(password), role, department))
        flash(f"{role.replace('_',' ').title()} account created.", "success")
    except sqlite3.IntegrityError:
        flash("That email is already in use.", "error")
    return redirect(url_for("dashboard"))


@app.route("/users/<int:user_id>/active", methods=["POST"])
@require_roles("dean")
def set_user_active(user_id):
    if user_id == session["user_id"]:
        flash("You cannot disable your own Dean account.", "error")
        return redirect(url_for("dashboard"))
    active = request.form.get("active") == "1"
    with connect_db() as db:
        if not db.execute("UPDATE users SET is_active=? WHERE id=?", (int(active), user_id)).rowcount:
            abort(404)
    flash("Account access updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/students/<int:student_id>/active", methods=["POST"])
@require_roles("hod", "dean")
def set_student_active(student_id):
    active = request.form.get("active") == "1"
    with connect_db() as db:
        student = db.execute("SELECT department FROM students WHERE id=?", (student_id,)).fetchone()
        if not student:
            abort(404)
        if session["role"] == "hod" and student["department"] != session["department"]:
            abort(403)
        db.execute("UPDATE students SET is_active=? WHERE id=?", (int(active),student_id))
    flash("Student account access updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/students/add", methods=["POST"])
@require_roles("hod", "dean")
def add_student():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    class_name = request.form.get("class_name", "").strip()
    department = session["department"] if session["role"] == "hod" else request.form.get("department", "").strip().upper()
    professor_id = request.form.get("professor_id", type=int)
    try:
        scores = [float(request.form.get(key, "0") or 0) for key in ("attendance", "marks", "assignments", "quiz")]
        if len(name) < 2 or "@" not in email or len(password) < 10 or not class_name or not department or any(x < 0 or x > 100 for x in scores):
            raise ValueError
        with connect_db() as db:
            if db.execute("SELECT 1 FROM users WHERE email=? COLLATE NOCASE UNION SELECT 1 FROM students WHERE email=? COLLATE NOCASE", (email, email)).fetchone():
                flash("That email is already in use.", "error")
                return redirect(url_for("dashboard"))
            professor = db.execute("SELECT id FROM users WHERE id=? AND role='professor' AND department=?", (professor_id, department)).fetchone() if professor_id else db.execute("SELECT id FROM users WHERE role='professor' AND department=? ORDER BY id LIMIT 1", (department,)).fetchone()
            db.execute("""INSERT INTO students(name,email,password_hash,department,class_name,professor_id,attendance,marks,assignments,quiz)
                VALUES(?,?,?,?,?,?,?,?,?,?)""", (name,email,generate_password_hash(password),department,class_name,professor["id"] if professor else None,*scores))
        flash(f"Student account for {name} created.", "success")
    except sqlite3.IntegrityError:
        flash("That email is already in use.", "error")
    except (ValueError, TypeError):
        flash("Check the student details and enter scores from 0 to 100.", "error")
    return redirect(url_for("dashboard"))


@app.route("/students/update-scores", methods=["POST"])
@require_roles("professor", "hod", "dean")
def update_scores():
    student_id = request.form.get("student_id", type=int)
    try:
        scores = [float(request.form.get(key, "")) for key in ("attendance", "marks", "assignments", "quiz")]
        if not student_id or any(x < 0 or x > 100 for x in scores):
            raise ValueError
        with connect_db() as db:
            if student_id not in {s["id"] for s in visible_students(db)}:
                abort(403)
            db.execute("UPDATE students SET attendance=?,marks=?,assignments=?,quiz=? WHERE id=?", (*scores,student_id))
        flash("Student progress updated.", "success")
    except (ValueError, TypeError):
        flash("Enter scores from 0 to 100.", "error")
    return redirect(url_for("dashboard"))


@app.route("/interventions/add", methods=["POST"])
@require_roles("professor", "hod", "dean")
def add_intervention():
    student_id = request.form.get("student_id", type=int)
    note = request.form.get("note", "").strip()
    if not student_id or not note:
        flash("Choose a student and add a follow-up note.", "error")
        return redirect(url_for("dashboard"))
    with connect_db() as db:
        if student_id not in {s["id"] for s in visible_students(db)}:
            abort(403)
        db.execute("INSERT INTO interventions(student_id,created_by,note) VALUES(?,?,?)", (student_id,session["user_id"],note[:500]))
    flash("Follow-up action added.", "success")
    return redirect(url_for("dashboard"))


@app.route("/interventions/<int:action_id>/close", methods=["POST"])
@require_roles("professor", "hod", "dean")
def close_intervention(action_id):
    with connect_db() as db:
        action = db.execute("SELECT student_id FROM interventions WHERE id=?", (action_id,)).fetchone()
        if not action or action["student_id"] not in {s["id"] for s in visible_students(db)}:
            abort(403)
        db.execute("UPDATE interventions SET status='Done' WHERE id=?", (action_id,))
    flash("Follow-up marked complete.", "success")
    return redirect(url_for("dashboard"))


@app.route("/attendance/mark", methods=["POST"])
@require_roles("professor", "hod", "dean")
def mark_attendance():
    student_id = request.form.get("student_id", type=int)
    status = request.form.get("status", "")
    attendance_date = request.form.get("attendance_date", "")
    if status not in {"Present", "Absent"} or not attendance_date:
        flash("Choose a valid date and attendance status.", "error")
        return redirect(url_for("dashboard"))
    with connect_db() as db:
        if student_id not in {s["id"] for s in visible_students(db)}:
            abort(403)
        db.execute("""INSERT INTO attendance_records(student_id,attendance_date,status,recorded_by) VALUES(?,?,?,?)
            ON CONFLICT(student_id,attendance_date) DO UPDATE SET status=excluded.status,recorded_by=excluded.recorded_by""",
            (student_id,attendance_date,status,session["user_id"]))
        totals = db.execute("SELECT COUNT(*) AS total,SUM(status='Present') AS present FROM attendance_records WHERE student_id=?", (student_id,)).fetchone()
        percent = round((totals["present"] or 0) * 100 / totals["total"], 1) if totals["total"] else 0
        db.execute("UPDATE students SET attendance=? WHERE id=?", (percent,student_id))
    flash("Attendance saved.", "success")
    return redirect(url_for("dashboard"))


@app.route("/announcements/add", methods=["POST"])
@require_roles("hod", "dean")
def add_announcement():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    department = session["department"] if session["role"] == "hod" else request.form.get("department", "ALL").strip().upper()
    if not title or not body:
        flash("Add a notice title and message.", "error")
        return redirect(url_for("dashboard"))
    with connect_db() as db:
        db.execute("INSERT INTO announcements(title,body,department,created_by) VALUES(?,?,?,?)", (title[:120],body[:1500],department,session["user_id"]))
    flash("Announcement posted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/labs/book", methods=["POST"])
@require_roles("professor", "lab_assistant")
def book_lab():
    equipment_id = request.form.get("equipment_id", type=int)
    booking_date = request.form.get("booking_date", "")
    start_time = request.form.get("start_time", "")
    end_time = request.form.get("end_time", "")
    purpose = request.form.get("purpose", "").strip()
    if not equipment_id or booking_date < date.today().isoformat() or not start_time or not end_time or start_time >= end_time or not purpose:
        flash("Check the lab booking details and choose a future/current date.", "error")
        return redirect(url_for("dashboard"))
    with connect_db() as db:
        item = db.execute("SELECT status FROM lab_equipment WHERE id=?", (equipment_id,)).fetchone()
        if not item or item["status"] != "Available":
            flash("That equipment is not available right now.", "error")
            return redirect(url_for("dashboard"))
        overlap = db.execute("""SELECT 1 FROM lab_bookings WHERE equipment_id=? AND booking_date=? AND status!='Cancelled'
            AND start_time < ? AND end_time > ?""", (equipment_id,booking_date,end_time,start_time)).fetchone()
        if overlap:
            flash("That time is already booked. Choose another slot.", "error")
            return redirect(url_for("dashboard"))
        db.execute("INSERT INTO lab_bookings(equipment_id,booked_by,booking_date,start_time,end_time,purpose) VALUES(?,?,?,?,?,?)",
                   (equipment_id,session["user_id"],booking_date,start_time,end_time,purpose[:300]))
    flash("Lab booking requested.", "success")
    return redirect(url_for("dashboard"))


@app.route("/labs/equipment/<int:item_id>/status", methods=["POST"])
@require_roles("lab_assistant", "dean")
def update_equipment(item_id):
    status = request.form.get("status", "")
    if status not in {"Available", "Maintenance", "Unavailable"}:
        abort(400)
    with connect_db() as db:
        if not db.execute("UPDATE lab_equipment SET status=? WHERE id=?", (status,item_id)).rowcount:
            abort(404)
    flash("Equipment status updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/labs/equipment/add", methods=["POST"])
@require_roles("lab_assistant", "dean")
def add_equipment():
    name = request.form.get("name", "").strip()
    lab_name = request.form.get("lab_name", "").strip()
    notes = request.form.get("notes", "").strip()
    if not name or not lab_name:
        flash("Enter the equipment name and lab.", "error")
        return redirect(url_for("dashboard"))
    with connect_db() as db:
        db.execute("INSERT INTO lab_equipment(name,lab_name,notes) VALUES(?,?,?)", (name[:120],lab_name[:120],notes[:300]))
    flash("Equipment added to the inventory.", "success")
    return redirect(url_for("dashboard"))


@app.route("/labs/bookings/<int:booking_id>/status", methods=["POST"])
@require_roles("lab_assistant", "dean")
def update_booking(booking_id):
    status = request.form.get("status", "")
    if status not in {"Approved", "Completed", "Cancelled"}:
        abort(400)
    with connect_db() as db:
        if not db.execute("UPDATE lab_bookings SET status=? WHERE id=?", (status,booking_id)).rowcount:
            abort(404)
    flash("Lab booking updated.", "success")
    return redirect(url_for("dashboard"))


@app.route("/reports/students.csv")
@require_roles("professor", "hod", "dean")
def export_students():
    fields = ["name", "email", "department", "class_name", "attendance", "marks", "assignments", "quiz"]
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(["Student", "College email", "Department", "Class", "Attendance %", "Marks %", "Assignments %", "Quiz %"])
    with connect_db() as db:
        for student in visible_students(db):
            row = []
            for field in fields:
                value = str(student[field])
                if value[:1] in {"=", "+", "-", "@"}:
                    value = "'" + value
                row.append(value)
            writer.writerow(row)
    response = make_response(stream.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=campuspulse-student-report.csv"
    return response


@app.errorhandler(403)
def forbidden(_error):
    return render_template("message.html", title="Access restricted", message="Your account does not have permission to view or change this information."), 403


@app.route("/health")
def health():
    return {"status": "ok"}


initialize_database()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
