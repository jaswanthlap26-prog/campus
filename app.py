
import os
from functools import wraps

from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, session, abort, flash
)

from werkzeug.security import check_password_hash
from dotenv import load_dotenv

from db import get_db_connection


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing from .env")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv(
        "SESSION_COOKIE_SECURE", "False"
    ).lower() == "true",
    PERMANENT_SESSION_LIFETIME=1800
)


# ==========================================
# ROLE CONFIGURATION
# ==========================================

ROLE_ALIASES = {
    "ADMIN": "SUPER_ADMIN"
}

ROLE_MENUS = {
    "STUDENT": [
        {"id": "overview", "label": "Dashboard", "icon": "⌂", "url": "/dashboard"},
        {"id": "profile", "label": "My Profile", "icon": "◉", "url": "/student/profile"},
        {"id": "my_faculty", "label": "My Faculty", "icon": "♙", "url": "/student/my-faculty"},
        {"id": "attendance", "label": "My Attendance", "icon": "▤", "url": "/student/attendance"},
        {"id": "events", "label": "Events", "icon": "▦", "url": "/student/events"},
        {"id": "clubs", "label": "Clubs", "icon": "♧", "url": "/student/clubs"},
        {"id": "announcements", "label": "Faculty Messages", "icon": "✉", "url": "/student/announcements"},
        {"id": "feedback", "label": "Feedback", "icon": "✉", "url": "/student/feedback"}
    ],

    "FACULTY": [
        {"id": "overview", "label": "Dashboard", "icon": "⌂", "url": "/dashboard"},
        {"id": "profile", "label": "My Profile", "icon": "◉", "url": "/faculty/profile"},
        {"id": "students", "label": "Students", "icon": "♙", "url": "/faculty/students"},
        {"id": "announcements", "label": "Announcements", "icon": "✉", "url": "/faculty/announcements"},
        {"id": "activities", "label": "Activities", "icon": "▦", "url": "/faculty/activities"}
    ],

    "HOD": [],
    "OPERATOR": [],
    "SUPER_ADMIN": []
}

ROLE_TEMPLATES = {
    "STUDENT": "student_dashboard.html",
    "FACULTY": "faculty_dashboard.html",
    "HOD": "hod_dashboard.html",
    "OPERATOR": "operator_dashboard.html",
    "SUPER_ADMIN": "superadmin_dashboard.html"
}


# ==========================================
# AUTHENTICATION DECORATORS
# ==========================================

def login_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            return redirect(url_for("home"))

        return function(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "user_id" not in session:
                return redirect(url_for("home"))

            if session.get("role") not in allowed_roles:
                abort(403)

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# DATABASE HELPERS
# ==========================================

def fetch_all(query, params=()):

    connection = get_db_connection()

    if connection is None:
        raise RuntimeError("Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor.fetchall()

    finally:
        if cursor:
            cursor.close()

        connection.close()


def fetch_one(query, params=()):

    connection = get_db_connection()

    if connection is None:
        raise RuntimeError("Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        return cursor.fetchone()

    finally:
        if cursor:
            cursor.close()

        connection.close()


# ==========================================
# LOGGED-IN STUDENT
# ==========================================

def get_logged_in_student():

    student_id = session.get("student_id")

    if not student_id:
        return None

    return fetch_one("""
        SELECT
            s.*,
            d.dept_name AS department,
            s.year_of_study AS year,
            s.mobile_number AS phone
        FROM students s
        LEFT JOIN departments d
            ON d.dept_id = s.dept_id
        WHERE s.student_id = %s
        LIMIT 1
    """, (student_id,))


# ==========================================
# LOGGED-IN FACULTY
# ==========================================

def get_logged_in_faculty():

    faculty_id = session.get("faculty_id")

    if not faculty_id:
        return None

    return fetch_one("""
        SELECT
            f.*,
            d.dept_name AS department
        FROM faculty f
        LEFT JOIN departments d
            ON d.dept_id = f.dept_id
        WHERE f.faculty_id = %s
        LIMIT 1
    """, (faculty_id,))


# ==========================================
# HOME
# ==========================================

@app.route("/")
def home():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# ==========================================
# LOGIN
# ==========================================

@app.route("/login", methods=["POST"])
def login():

    role = request.form.get("role", "").strip().upper()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not role or not username or not password:
        return render_template(
            "login.html",
            error="Please fill in all fields."
        )

    selected_role = ROLE_ALIASES.get(role, role)

    connection = get_db_connection()

    if connection is None:
        return render_template(
            "login.html",
            error="Database connection failed."
        )

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                user_id,
                username,
                password_hash,
                role,
                student_id,
                faculty_id,
                is_active
            FROM user_accounts
            WHERE username = %s
            LIMIT 1
        """, (username,))

        account = cursor.fetchone()

        if not account:
            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        if not account["is_active"]:
            return render_template(
                "login.html",
                error="Your account is inactive."
            )

        if not check_password_hash(
            account["password_hash"], password
        ):
            return render_template(
                "login.html",
                error="Invalid username or password."
            )

        actual_role = account["role"].upper()
        actual_role = ROLE_ALIASES.get(
            actual_role, actual_role
        )

        if selected_role != actual_role:
            return render_template(
                "login.html",
                error="Incorrect login role selected."
            )

        if actual_role not in ROLE_TEMPLATES:
            return render_template(
                "login.html",
                error="Account role is not configured."
            )

        session.clear()
        session.permanent = True

        session["user_id"] = account["user_id"]
        session["username"] = account["username"]
        session["role"] = actual_role
        session["student_id"] = account["student_id"]
        session["faculty_id"] = account["faculty_id"]

        if actual_role == "SUPER_ADMIN":
            return redirect(url_for("superadmin_dashboard"))

        return redirect(url_for("dashboard"))

    except Exception:
        app.logger.exception("Login error")

        return render_template(
            "login.html",
            error="Login failed. Please try again."
        )

    finally:
        if cursor:
            cursor.close()

        connection.close()


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/dashboard")
@login_required
def dashboard():

    role = session.get("role")

    if role == "SUPER_ADMIN":
        return redirect(url_for("superadmin_dashboard"))

    if role == "OPERATOR":
        return redirect(url_for("operator_dashboard"))

    template = ROLE_TEMPLATES.get(role)

    if not template:
        abort(403)

    student = None
    faculty = None
    faculty_stats = {}

    try:

        if role == "STUDENT":

            student = get_logged_in_student()

            if not student:
                abort(404)

        elif role == "FACULTY":

            faculty = get_logged_in_faculty()

            if not faculty:
                abort(404)

            faculty_stats["students"] = fetch_one("""
                SELECT COUNT(*) AS total
                FROM students
                WHERE dept_id = %s
            """, (faculty["dept_id"],))["total"]

            faculty_stats["announcements"] = fetch_one("""
                SELECT COUNT(*) AS total
                FROM faculty_announcements
                WHERE faculty_id = %s
                  AND is_active = TRUE
            """, (faculty["faculty_id"],))["total"]

            faculty_stats["activities"] = fetch_one("""
                SELECT COUNT(*) AS total
                FROM events
                WHERE is_active = TRUE
            """)["total"]

    except Exception:
        app.logger.exception("Dashboard loading error")
        abort(500)

    return render_template(
        template,
        page_title=role.replace("_", " ").title(),
        nav_items=ROLE_MENUS[role],
        active_page="overview",
        student=student or {},
        faculty=faculty or {},
        faculty_stats=faculty_stats
    )


# ==========================================
# STUDENT PROFILE
# ==========================================

@app.route("/student/profile")
@login_required
@role_required("STUDENT")
def student_profile():

    try:
        student = get_logged_in_student()

        if not student:
            abort(404)

    except Exception:
        app.logger.exception("Student profile error")
        abort(500)

    return render_template(
        "student_profile.html",
        student=student,
        page_title="My Profile",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="profile"
    )


# ==========================================
# STUDENT - MY FACULTY
# ==========================================

@app.route("/student/my-faculty")
@login_required
@role_required("STUDENT")
def student_my_faculty():

    try:
        student = get_logged_in_student()

        if not student:
            abort(404)

        # Show all faculty members from the logged-in student's department.
        # No faculty-subject-section assignment table is required.
        faculty_list = fetch_all("""
            SELECT
                faculty_id,
                faculty_name,
                designation,
                email,
                mobile_number
            FROM faculty
            WHERE dept_id = %s
            ORDER BY faculty_name
        """, (student["dept_id"],))

    except Exception:
        app.logger.exception("Student My Faculty loading error")
        abort(500)

    html = r"""
    {% extends "base.html" %}

    {% block title %}My Faculty | Campus Connect{% endblock %}

    {% block content %}
    <style>
        .my-faculty-page{max-width:1150px;margin:0 auto;padding:10px 0 30px}
        .my-faculty-heading{margin-bottom:22px}
        .my-faculty-heading h1{margin:0 0 7px;font-size:28px;color:var(--text-primary,#172033)}
        .my-faculty-heading p{margin:0;color:var(--text-secondary,#64748b)}
        .faculty-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:18px}
        .faculty-card{background:var(--card-bg,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:14px;padding:20px;box-shadow:0 4px 14px rgba(15,23,42,.05)}
        .faculty-card-top{display:flex;gap:13px;align-items:center;margin-bottom:16px}
        .faculty-avatar{width:48px;height:48px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#e8efff;color:#2456b3;font-weight:700;font-size:19px;flex-shrink:0}
        .faculty-card h2{font-size:17px;margin:0 0 4px;color:var(--text-primary,#172033)}
        .faculty-designation{font-size:13px;color:var(--text-secondary,#64748b)}
        .faculty-detail{display:flex;gap:9px;align-items:flex-start;padding:9px 0;border-top:1px solid var(--border-color,#edf0f5);font-size:14px;color:var(--text-primary,#334155);overflow-wrap:anywhere}
        .faculty-detail strong{min-width:78px;color:var(--text-secondary,#64748b);font-weight:600}
        .faculty-detail a{color:var(--link-color,#2563eb);text-decoration:none}
        .faculty-detail a:hover{text-decoration:underline}
        .faculty-empty{padding:34px 20px;text-align:center;background:var(--card-bg,#fff);border:1px dashed var(--border-color,#cbd5e1);border-radius:14px;color:var(--text-secondary,#64748b)}
        .faculty-empty h2{margin:0 0 8px;color:var(--text-primary,#172033);font-size:19px}
        @media(max-width:600px){.my-faculty-page{padding-top:4px}.my-faculty-heading h1{font-size:24px}.faculty-grid{grid-template-columns:1fr}}
    </style>

    <section class="my-faculty-page">
        <div class="my-faculty-heading">
            <h1>My Faculty</h1>
            <p>Faculty members from your department.</p>
        </div>

        {% if faculty_list %}
            <div class="faculty-grid">
                {% for faculty in faculty_list %}
                    <article class="faculty-card">
                        <div class="faculty-card-top">
                            <div class="faculty-avatar">
                                {{ faculty.faculty_name[:1]|upper }}
                            </div>
                            <div>
                                <h2>{{ faculty.faculty_name }}</h2>
                                <div class="faculty-designation">
                                    {{ faculty.designation or "Faculty Member" }}
                                </div>
                            </div>
                        </div>

                        <div class="faculty-detail">
                            <strong>Email</strong>
                            <span>
                                {% if faculty.email %}
                                    <a href="mailto:{{ faculty.email }}">{{ faculty.email }}</a>
                                {% else %}
                                    Not provided
                                {% endif %}
                            </span>
                        </div>
                        <div class="faculty-detail">
                            <strong>Phone</strong>
                            <span>
                                {% if faculty.mobile_number %}
                                    <a href="tel:{{ faculty.mobile_number }}">{{ faculty.mobile_number }}</a>
                                {% else %}
                                    Not provided
                                {% endif %}
                            </span>
                        </div>
                    </article>
                {% endfor %}
            </div>
        {% else %}
            <div class="faculty-empty">
                <h2>No faculty details found</h2>
                <p>There are currently no faculty members listed for your department.</p>
            </div>
        {% endif %}
    </section>
    {% endblock %}
    """

    return render_template_string(
        html,
        student=student,
        faculty_list=faculty_list,
        page_title="My Faculty",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="my_faculty"
    )


# ==========================================
# STUDENT SUBJECT-WISE ATTENDANCE
# ==========================================

@app.route("/student/attendance")
@login_required
@role_required("STUDENT")
def student_attendance():

    try:
        student = get_logged_in_student()

        if not student:
            abort(404)

        student_id = student["student_id"]

        # Use the existing subject-wise summary table for the official
        # total_classes and attended_classes values. Attendance rows are
        # used only for the present/absent/late breakdown and history.
        subjects = fetch_all("""
            SELECT
                sa.subject_id,
                COALESCE(sub.subject_code, 'N/A') AS subject_code,
                COALESCE(sub.subject_name, 'Subject not linked') AS subject_name,
                COALESCE(sa.total_classes, 0) AS total_classes,
                COALESCE(sa.attended_classes, 0) AS attended_classes,
                COALESCE(att.present_classes, 0) AS present_classes,
                COALESCE(att.absent_classes, 0) AS absent_classes,
                COALESCE(att.late_classes, 0) AS late_classes
            FROM student_attendance sa
            LEFT JOIN subjects sub
                ON sub.subject_id = sa.subject_id
            LEFT JOIN (
                SELECT
                    student_id,
                    subject_id,
                    SUM(CASE WHEN attendance_status = 'PRESENT' THEN 1 ELSE 0 END) AS present_classes,
                    SUM(CASE WHEN attendance_status = 'ABSENT' THEN 1 ELSE 0 END) AS absent_classes,
                    SUM(CASE WHEN attendance_status = 'LATE' THEN 1 ELSE 0 END) AS late_classes
                FROM attendance
                WHERE student_id = %s
                GROUP BY student_id, subject_id
            ) att
                ON att.student_id = sa.student_id
                AND att.subject_id = sa.subject_id
            WHERE sa.student_id = %s
            ORDER BY subject_name
        """, (student_id, student_id))

        total_classes = 0
        total_attended = 0
        total_present = 0
        total_absent = 0
        total_late = 0

        for subject in subjects:
            subject["total_classes"] = int(subject["total_classes"] or 0)
            subject["attended_classes"] = int(subject["attended_classes"] or 0)
            subject["present_classes"] = int(subject["present_classes"] or 0)
            subject["absent_classes"] = int(subject["absent_classes"] or 0)
            subject["late_classes"] = int(subject["late_classes"] or 0)

            subject["percentage"] = round(
                (subject["attended_classes"] / subject["total_classes"] * 100), 1
            ) if subject["total_classes"] else 0

            total_classes += subject["total_classes"]
            total_attended += subject["attended_classes"]
            total_present += subject["present_classes"]
            total_absent += subject["absent_classes"]
            total_late += subject["late_classes"]

        overall_percentage = round(
            (total_attended / total_classes * 100), 1
        ) if total_classes else 0

        # Actual date-wise records for this student only.
        attendance_history = fetch_all("""
            SELECT
                a.attendance_id,
                DATE_FORMAT(a.attendance_date, '%d %b %Y') AS attendance_date,
                a.attendance_status,
                a.remarks,
                COALESCE(sub.subject_code, 'N/A') AS subject_code,
                COALESCE(sub.subject_name, 'Subject not linked') AS subject_name
            FROM attendance a
            LEFT JOIN subjects sub
                ON sub.subject_id = a.subject_id
            WHERE a.student_id = %s
            ORDER BY a.attendance_date DESC, a.attendance_id DESC
        """, (student_id,))

    except Exception:
        app.logger.exception("Student attendance loading error")
        abort(500)

    html = r"""
    {% extends "base.html" %}

    {% block title %}My Attendance | Campus Connect{% endblock %}

    {% block content %}
    <style>
        .attendance-page{max-width:1150px;margin:0 auto;padding:10px 0 32px}
        .attendance-heading{margin-bottom:22px}
        .attendance-heading h1{margin:0 0 7px;font-size:28px;color:var(--text-primary,#172033)}
        .attendance-heading p{margin:0;color:var(--text-secondary,#64748b)}
        .attendance-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:14px;margin-bottom:22px}
        .attendance-stat{background:var(--card-bg,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:15px;padding:18px}
        .attendance-stat span{display:block;color:var(--text-secondary,#64748b);font-size:13px;margin-bottom:8px}
        .attendance-stat strong{font-size:25px;color:var(--text-primary,#172033)}
        .attendance-panel{background:var(--card-bg,#fff);border:1px solid var(--border-color,#e2e8f0);border-radius:16px;padding:20px;margin-bottom:22px}
        .attendance-panel h2{font-size:19px;margin:0 0 17px;color:var(--text-primary,#172033)}
        .subject-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:15px}
        .subject-card{border:1px solid var(--border-color,#e2e8f0);border-radius:13px;padding:16px;min-width:0}
        .subject-top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:13px}
        .subject-top h3{font-size:16px;margin:0 0 4px;color:var(--text-primary,#172033)}
        .subject-code{font-size:12px;color:var(--text-secondary,#64748b)}
        .subject-percent{font-weight:750;font-size:20px;white-space:nowrap}
        .good{color:#15945b}.low{color:#dc5555}
        .attendance-track{height:8px;background:var(--border-color,#e2e8f0);border-radius:30px;overflow:hidden;margin:12px 0}
        .attendance-fill{height:100%;border-radius:30px}
        .subject-counts{display:flex;flex-wrap:wrap;gap:8px 14px;color:var(--text-secondary,#64748b);font-size:12px}
        .history-table-wrap{overflow-x:auto}
        .history-table{width:100%;border-collapse:collapse;min-width:570px}
        .history-table th,.history-table td{text-align:left;padding:12px 10px;border-bottom:1px solid var(--border-color,#e2e8f0);font-size:13px}
        .history-table th{color:var(--text-secondary,#64748b);font-weight:650}
        .status-pill{display:inline-block;padding:5px 9px;border-radius:30px;font-size:11px;font-weight:700}
        .status-PRESENT{background:#e7f7ee;color:#137b49}.status-ABSENT{background:#fff0f0;color:#c43c3c}.status-LATE{background:#fff5df;color:#a56a00}
        .empty-attendance{padding:25px;text-align:center;color:var(--text-secondary,#64748b);border:1px dashed var(--border-color,#cbd5e1);border-radius:12px}
        @media(max-width:600px){.attendance-panel{padding:14px}.attendance-heading h1{font-size:24px}}
    </style>

    <div class="attendance-page">
        <div class="attendance-heading">
            <h1>My Attendance</h1>
            <p>View your subject-wise attendance and daily attendance records.</p>
        </div>

        <div class="attendance-summary">
            <div class="attendance-stat">
                <span>Overall Attendance</span>
                <strong class="{{ 'good' if overall_percentage >= 75 else 'low' }}">{{ overall_percentage }}%</strong>
            </div>
            <div class="attendance-stat">
                <span>Attended Classes</span>
                <strong>{{ total_attended }}</strong>
            </div>
            <div class="attendance-stat">
                <span>Total Classes</span>
                <strong>{{ total_classes }}</strong>
            </div>
            <div class="attendance-stat">
                <span>Absent Classes</span>
                <strong>{{ total_absent }}</strong>
            </div>
        </div>

        <section class="attendance-panel">
            <h2>Subject-wise Attendance</h2>
            {% if subjects %}
            <div class="subject-list">
                {% for subject in subjects %}
                <article class="subject-card">
                    <div class="subject-top">
                        <div>
                            <h3>{{ subject.subject_name }}</h3>
                            <div class="subject-code">{{ subject.subject_code or 'Subject' }}</div>
                        </div>
                        <div class="subject-percent {{ 'good' if subject.percentage >= 75 else 'low' }}">{{ subject.percentage }}%</div>
                    </div>
                    <div class="attendance-track">
                        <div class="attendance-fill" style="width:{{ subject.percentage }}%;background:{{ '#15945b' if subject.percentage >= 75 else '#dc5555' }}"></div>
                    </div>
                    <div class="subject-counts">
                        <span><b>{{ subject.attended_classes }}</b> attended</span>
                        <span><b>{{ subject.total_classes }}</b> total</span>
                        <span><b>{{ subject.absent_classes }}</b> absent</span>
                        <span><b>{{ subject.late_classes }}</b> late</span>
                    </div>
                </article>
                {% endfor %}
            </div>
            {% else %}
            <div class="empty-attendance">No attendance records have been marked for your account yet.</div>
            {% endif %}
        </section>

        <section class="attendance-panel">
            <h2>Attendance History</h2>
            {% if attendance_history %}
            <div class="history-table-wrap">
                <table class="history-table">
                    <thead><tr><th>Date</th><th>Subject</th><th>Status</th><th>Remarks</th></tr></thead>
                    <tbody>
                    {% for record in attendance_history %}
                        <tr>
                            <td>{{ record.attendance_date }}</td>
                            <td>{{ record.subject_name }} <span class="subject-code">({{ record.subject_code }})</span></td>
                            <td><span class="status-pill status-{{ record.attendance_status }}">{{ record.attendance_status }}</span></td>
                            <td>{{ record.remarks or '—' }}</td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="empty-attendance">No attendance records have been marked for you yet.</div>
            {% endif %}
        </section>
    </div>
    {% endblock %}
    """

    return render_template_string(
        html,
        student=student,
        subjects=subjects,
        attendance_history=attendance_history,
        total_classes=total_classes,
        total_attended=total_attended,
        total_present=total_present,
        total_absent=total_absent,
        total_late=total_late,
        overall_percentage=overall_percentage,
        page_title="My Attendance",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="attendance"
    )


# ==========================================
# STUDENT CLUBS
# ==========================================

@app.route("/student/clubs")
@login_required
@role_required("STUDENT")
def student_clubs():

    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    try:

        clubs = fetch_all("""
            SELECT
                c.club_id,
                c.club_code,
                c.club_name,
                c.category,
                c.description,
                c.dept_id,
                c.coordinator_faculty_id,
                d.dept_name
            FROM clubs c
            LEFT JOIN departments d
                ON d.dept_id = c.dept_id
            ORDER BY c.club_name
        """)

        memberships = fetch_all("""
            SELECT
                cm.membership_id,
                cm.student_id,
                cm.club_id,
                cm.membership_type,
                cm.membership_status,
                c.club_name,
                c.club_code,
                c.category
            FROM club_memberships cm
            LEFT JOIN clubs c
                ON c.club_id = cm.club_id
            WHERE cm.student_id = %s
              AND cm.membership_status = 'ACTIVE'
            ORDER BY
                CASE
                    WHEN cm.membership_type = 'PRIMARY'
                    THEN 0 ELSE 1
                END,
                c.club_name
        """, (student_id,))

        joined_club_ids = {
            membership["club_id"]
            for membership in memberships
        }

        for club in clubs:
            club["is_joined"] = (
                club["club_id"] in joined_club_ids
            )

    except Exception:
        app.logger.exception("Student clubs loading error")
        abort(500)

    return render_template(
        "student_clubs.html",
        clubs=clubs,
        memberships=memberships,
        page_title="Explore Clubs",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="clubs"
    )


# ==========================================
# JOIN OR CHANGE CLUB
# ==========================================

@app.route(
    "/student/clubs/<int:club_id>/join",
    methods=["POST"]
)
@login_required
@role_required("STUDENT")
def student_club_join(club_id):

    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    membership_type = request.form.get(
        "membership_type", ""
    ).strip().upper()

    if membership_type not in ("PRIMARY", "ADDITIONAL"):
        return "Invalid membership type.", 400

    connection = get_db_connection()

    if connection is None:
        abort(500)

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT club_id
            FROM clubs
            WHERE club_id = %s
        """, (club_id,))

        if not cursor.fetchone():
            return "Club not found.", 404

        if membership_type == "PRIMARY":
            cursor.execute("""
                UPDATE club_memberships
                SET membership_type = 'ADDITIONAL'
                WHERE student_id = %s
                  AND membership_type = 'PRIMARY'
                  AND membership_status = 'ACTIVE'
            """, (student_id,))

        cursor.execute("""
            INSERT INTO club_memberships
            (
                student_id,
                club_id,
                membership_type,
                membership_status
            )
            VALUES (%s, %s, %s, 'ACTIVE')
            ON DUPLICATE KEY UPDATE
                membership_type = VALUES(membership_type),
                membership_status = 'ACTIVE'
        """, (student_id, club_id, membership_type))

        connection.commit()

        return redirect(
            url_for("student_clubs", message="joined")
        )

    except Exception:
        connection.rollback()
        app.logger.exception("Club joining error")
        return "Club joining failed.", 500

    finally:
        if cursor:
            cursor.close()

        connection.close()


# ==========================================
# STUDENT EVENTS
# ==========================================

@app.route("/student/events")
@login_required
@role_required("STUDENT")
def student_events():

    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    try:

        events = fetch_all("""
            SELECT
                e.event_id,
                e.event_name,
                e.description,
                e.category,
                DATE_FORMAT(
                    e.event_date, '%d %b %Y'
                ) AS event_date,
                e.event_time,
                e.venue,
                CASE
                    WHEN er.registration_id IS NOT NULL
                    THEN 1 ELSE 0
                END AS is_registered
            FROM events e
            LEFT JOIN event_registrations er
                ON er.event_id = e.event_id
                AND er.student_id = %s
                AND er.registration_status = 'REGISTERED'
            WHERE e.is_active = TRUE
            ORDER BY e.event_date, e.event_time
        """, (student_id,))

    except Exception:
        app.logger.exception("Student events loading error")
        abort(500)

    return render_template(
        "student_events.html",
        events=events,
        page_title="Campus Events",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="events"
    )


# ==========================================
# EVENT REGISTRATION
# ==========================================

@app.route(
    "/student/events/<int:event_id>/register",
    methods=["POST"]
)
@login_required
@role_required("STUDENT")
def student_event_register(event_id):

    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    connection = get_db_connection()

    if connection is None:
        abort(500)

    cursor = None

    try:
        cursor = connection.cursor()

        cursor.execute("""
            SELECT event_id
            FROM events
            WHERE event_id = %s
              AND is_active = TRUE
        """, (event_id,))

        if not cursor.fetchone():
            return "Event not found.", 404

        cursor.execute("""
            INSERT IGNORE INTO event_registrations
            (
                event_id,
                student_id,
                registration_status
            )
            VALUES (%s, %s, 'REGISTERED')
        """, (event_id, student_id))

        if cursor.rowcount == 1:
            connection.commit()
            message = "registered"
        else:
            connection.rollback()
            message = "already_registered"

    except Exception:
        connection.rollback()
        app.logger.exception("Event registration error")
        return "Event registration failed.", 500

    finally:
        if cursor:
            cursor.close()

        connection.close()

    return redirect(
        url_for("student_events", message=message)
    )


# ==========================================
# FACULTY PROFILE
# ==========================================

@app.route("/faculty/profile")
@login_required
@role_required("FACULTY")
def faculty_profile():

    try:
        faculty = get_logged_in_faculty()

        if not faculty:
            abort(404)

    except Exception:
        app.logger.exception("Faculty profile loading error")
        abort(500)

    return render_template(
        "faculty_profile.html",
        faculty=faculty,
        page_title="My Profile",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="profile"
    )


# ==========================================
# FACULTY STUDENTS
# ==========================================

@app.route("/faculty/students")
@login_required
@role_required("FACULTY")
def faculty_students():

    try:

        faculty = get_logged_in_faculty()

        if not faculty:
            abort(404)

        search = request.args.get("q", "").strip()

        students = fetch_all("""
            SELECT
                s.student_id,
                s.student_code,
                s.roll_number,
                s.student_name,
                s.mobile_number,
                s.year_of_study,
                s.semester,
                d.dept_name,
                sec.section_name,
                sec.academic_year
            FROM students s
            LEFT JOIN departments d
                ON d.dept_id = s.dept_id
            LEFT JOIN sections sec
                ON sec.section_id = s.section_id
            WHERE s.dept_id = %s
              AND (
                    s.student_name LIKE %s
                    OR s.roll_number LIKE %s
                    OR s.student_code LIKE %s
                  )
            ORDER BY sec.section_name, s.roll_number
        """, (
            faculty["dept_id"],
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ))

    except Exception:
        app.logger.exception("Faculty students loading error")
        abort(500)

    return render_template(
        "faculty_students.html",
        faculty=faculty,
        students=students,
        search=search,
        page_title="Students",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="students"
    )


# ==========================================
# FACULTY ANNOUNCEMENTS
# ==========================================

@app.route(
    "/faculty/announcements",
    methods=["GET", "POST"]
)
@login_required
@role_required("FACULTY")
def faculty_announcements():

    error = None
    success = None

    try:

        faculty_id = session.get("faculty_id")

        if not faculty_id:
            abort(403)

        departments = fetch_all("""
            SELECT dept_id, dept_name
            FROM departments
            ORDER BY dept_name
        """)

        subjects = fetch_all("""
            SELECT
                subject_id,
                dept_id,
                subject_code,
                subject_name
            FROM subjects
            ORDER BY subject_name
        """)

        if request.method == "POST":

            dept_id = request.form.get(
                "dept_id", ""
            ).strip()

            year = request.form.get(
                "year_of_study", ""
            ).strip()

            subject_id = request.form.get(
                "subject_id", ""
            ).strip()

            title = request.form.get(
                "title", ""
            ).strip()

            message = request.form.get(
                "message", ""
            ).strip()

            if not all([
                dept_id, year, subject_id, title, message
            ]):
                error = "Please fill in all fields."

            elif not year.isdigit() or not 1 <= int(year) <= 6:
                error = "Please select a valid year."

            elif len(title) > 200 or len(message) > 5000:
                error = "Title or message is too long."

            else:

                valid_subject = fetch_one("""
                    SELECT subject_id
                    FROM subjects
                    WHERE subject_id = %s
                      AND dept_id = %s
                """, (subject_id, dept_id))

                if not valid_subject:
                    error = "Invalid subject for selected department."

                else:

                    connection = get_db_connection()

                    if connection is None:
                        raise RuntimeError(
                            "Database connection failed."
                        )

                    cursor = None

                    try:
                        cursor = connection.cursor()

                        cursor.execute("""
                            INSERT INTO faculty_announcements
                            (
                                faculty_id,
                                dept_id,
                                year_of_study,
                                subject_id,
                                title,
                                message
                            )
                            VALUES (%s, %s, %s, %s, %s, %s)
                        """, (
                            faculty_id,
                            dept_id,
                            int(year),
                            subject_id,
                            title,
                            message
                        ))

                        connection.commit()
                        success = "Announcement published successfully."

                    except Exception:
                        connection.rollback()
                        app.logger.exception(
                            "Announcement publishing error"
                        )
                        error = "Could not publish announcement."

                    finally:
                        if cursor:
                            cursor.close()

                        connection.close()

        announcements = fetch_all("""
            SELECT
                a.announcement_id,
                a.title,
                a.message,
                a.year_of_study,
                a.created_at,
                d.dept_name,
                s.subject_name
            FROM faculty_announcements a
            JOIN departments d
                ON d.dept_id = a.dept_id
            JOIN subjects s
                ON s.subject_id = a.subject_id
            WHERE a.faculty_id = %s
              AND a.is_active = TRUE
            ORDER BY a.created_at DESC
        """, (faculty_id,))

    except Exception:
        app.logger.exception(
            "Faculty announcements loading error"
        )
        abort(500)

    return render_template(
        "faculty_announcements.html",
        departments=departments,
        subjects=subjects,
        announcements=announcements,
        error=error,
        success=success,
        page_title="Faculty Announcements",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="announcements"
    )


# ==========================================
# FACULTY ACTIVITIES
# ==========================================

@app.route("/faculty/activities")
@login_required
@role_required("FACULTY")
def faculty_activities():

    try:

        faculty = get_logged_in_faculty()

        if not faculty:
            abort(404)

        activities = fetch_all("""
            SELECT
                event_id,
                event_name,
                description,
                category,
                event_date,
                event_time,
                venue
            FROM events
            WHERE is_active = TRUE
            ORDER BY event_date DESC, event_time DESC
        """)

    except Exception:
        app.logger.exception("Faculty activities loading error")
        abort(500)

    return render_template(
        "faculty_activities.html",
        faculty=faculty,
        activities=activities,
        page_title="Campus Activities",
        nav_items=ROLE_MENUS["FACULTY"],
        active_page="activities"
    )


# ==========================================
# STUDENT FACULTY MESSAGES
# ==========================================

@app.route("/student/announcements")
@login_required
@role_required("STUDENT")
def student_announcements():

    student_id = session.get("student_id")

    if not student_id:
        abort(403)

    try:

        student = fetch_one("""
            SELECT
                s.student_id,
                s.student_name,
                s.dept_id,
                s.year_of_study,
                d.dept_name
            FROM students s
            LEFT JOIN departments d
                ON d.dept_id = s.dept_id
            WHERE s.student_id = %s
            LIMIT 1
        """, (student_id,))

        if not student:
            abort(404)

        announcements = fetch_all("""
            SELECT
                a.announcement_id,
                a.title,
                a.message,
                a.created_at,
                a.year_of_study,
                s.subject_name,
                s.subject_code,
                d.dept_name
            FROM faculty_announcements a
            INNER JOIN subjects s
                ON s.subject_id = a.subject_id
            INNER JOIN departments d
                ON d.dept_id = a.dept_id
            WHERE a.is_active = TRUE
              AND a.dept_id = %s
              AND a.year_of_study = %s
            ORDER BY a.created_at DESC
        """, (
            student["dept_id"],
            student["year_of_study"]
        ))

    except Exception:
        app.logger.exception(
            "Student announcements loading error"
        )
        abort(500)

    return render_template(
        "student_announcements.html",
        announcements=announcements,
        student=student,
        page_title="Faculty Messages",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="announcements"
    )


# ==========================================
# STUDENT FEEDBACK
# ==========================================

@app.route(
    "/student/feedback",
    methods=["GET", "POST"]
)
@login_required
@role_required("STUDENT")
def student_feedback():

    error = None
    success = None

    if request.method == "POST":

        feedback = request.form.get(
            "feedback", ""
        ).strip()

        if not feedback:
            error = "Please enter your feedback."

        elif len(feedback) > 3000:
            error = "Feedback cannot exceed 3000 characters."

        elif not session.get("student_id"):
            abort(403)

        else:

            connection = get_db_connection()

            if connection is None:
                error = "Database connection failed."

            else:
                cursor = None

                try:
                    cursor = connection.cursor()

                    cursor.execute("""
                        INSERT INTO student_feedback
                        (
                            student_id,
                            feedback_text
                        )
                        VALUES (%s, %s)
                    """, (
                        session["student_id"],
                        feedback
                    ))

                    connection.commit()
                    success = "Your feedback was submitted successfully."

                except Exception:
                    connection.rollback()
                    app.logger.exception(
                        "Feedback submission error"
                    )
                    error = "Could not submit feedback. Please try again."

                finally:
                    if cursor:
                        cursor.close()

                    connection.close()

    return render_template(
        "student_feedback.html",
        error=error,
        success=success,
        page_title="Feedback",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="feedback"
    )


# ==========================================
# SUPER ADMIN - VIEW STUDENTS
# ==========================================

@app.route("/superadmin/students")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_students():

    search = request.args.get("q", "").strip()

    try:
        students = fetch_all("""
            SELECT
                s.student_id,
                s.student_code,
                s.roll_number,
                s.student_name,
                s.mobile_number,
                s.year_of_study,
                s.semester,
                d.dept_name,
                sec.section_name
            FROM students s
            LEFT JOIN departments d
                ON d.dept_id = s.dept_id
            LEFT JOIN sections sec
                ON sec.section_id = s.section_id
            WHERE
                s.student_name LIKE %s
                OR s.student_code LIKE %s
                OR s.roll_number LIKE %s
                OR d.dept_name LIKE %s
            ORDER BY s.student_name
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ))

    except Exception:
        app.logger.exception("Super Admin students loading error")
        abort(500)

    return render_template(
        "superadmin_students.html",
        students=students,
        search=search,
        total=len(students)
    )


# ==========================================
# SUPER ADMIN - VIEW FACULTY
# ==========================================

@app.route("/superadmin/faculty")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_faculty():

    search = request.args.get("q", "").strip()

    try:
        faculty_members = fetch_all("""
            SELECT
                f.faculty_id,
                f.faculty_code,
                f.faculty_no,
                f.faculty_name,
                f.designation,
                f.degrees,
                f.mobile_number,
                f.email,
                d.dept_name
            FROM faculty f
            LEFT JOIN departments d
                ON d.dept_id = f.dept_id
            WHERE
                f.faculty_name LIKE %s
                OR f.faculty_code LIKE %s
                OR f.email LIKE %s
                OR d.dept_name LIKE %s
            ORDER BY f.faculty_name
        """, (
            f"%{search}%",
            f"%{search}%",
            f"%{search}%",
            f"%{search}%"
        ))

    except Exception:
        app.logger.exception("Super Admin faculty loading error")
        abort(500)

    return render_template(
        "superadmin_faculty.html",
        faculty_members=faculty_members,
        search=search,
        total=len(faculty_members)
    )


# ==========================================
# SUPER ADMIN - VIEW DEPARTMENTS
# ==========================================

@app.route("/superadmin/departments")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_departments():

    search = request.args.get("q", "").strip()

    try:
        departments = fetch_all("""
            SELECT
                dept_id,
                dept_name
            FROM departments
            WHERE dept_name LIKE %s
            ORDER BY dept_name
        """, (f"%{search}%",))

    except Exception:
        app.logger.exception(
            "Super Admin departments loading error"
        )
        abort(500)

    return render_template(
        "superadmin_departments.html",
        departments=departments,
        search=search,
        total=len(departments)
    )


# ==========================================
# SUPER ADMIN DASHBOARD
# ==========================================

@app.route("/superadmin/dashboard")
@login_required
@role_required("SUPER_ADMIN")
def superadmin_dashboard():

    connection = get_db_connection()

    if connection is None:
        abort(500)

    cursor = None

    stats = {
        "students": 0,
        "faculty": 0,
        "departments": 0,
        "sections": 0,
        "users": 0
    }

    try:
        cursor = connection.cursor(dictionary=True)

        tables = {
            "students": "students",
            "faculty": "faculty",
            "departments": "departments",
            "sections": "sections",
            "users": "user_accounts"
        }

        for key, table in tables.items():

            cursor.execute(
                f"SELECT COUNT(*) AS total FROM `{table}`"
            )

            result = cursor.fetchone()
            stats[key] = result["total"]

    except Exception:
        app.logger.exception(
            "Super Admin dashboard loading error"
        )
        abort(500)

    finally:
        if cursor:
            cursor.close()

        connection.close()

    return render_template(
        "superadmin_dashboard.html",
        stats=stats,
        page_title="Super Admin Dashboard"
    )


# ==========================================
# OPERATOR DASHBOARD
# ==========================================

@app.route("/operator/dashboard")
@login_required
@role_required("OPERATOR")
def operator_dashboard():

    try:
        stats = {
            "students": fetch_one(
                "SELECT COUNT(*) AS total FROM students"
            )["total"],
            "faculty": fetch_one(
                "SELECT COUNT(*) AS total FROM faculty"
            )["total"]
        }

    except Exception:
        app.logger.exception("Operator dashboard loading error")
        abort(500)

    return render_template(
        "operator_dashboard.html",
        stats=stats
    )


# ==========================================
# OPERATOR - RECORD MANAGEMENT HELPERS
# ==========================================

OPERATOR_TABLES = {
    "students": {"label": "Student", "pk": "student_id", "title": "Student Records"},
    "faculty": {"label": "Faculty", "pk": "faculty_id", "title": "Faculty Records"},
    "clubs": {"label": "Club", "pk": "club_id", "title": "Club Records"},
    "departments": {"label": "Department", "pk": "dept_id", "title": "Department Records"}
}


def operator_table_columns(table):
    """Read the real columns from the existing database table."""
    if table not in OPERATOR_TABLES:
        abort(404)

    connection = get_db_connection()
    if connection is None:
        raise RuntimeError("Database connection failed.")
    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(f"SHOW COLUMNS FROM `{table}`")
        return cursor.fetchall()
    finally:
        if cursor:
            cursor.close()
        connection.close()


def operator_form_fields(table):
    """Build safe form metadata from the actual table schema."""
    columns = operator_table_columns(table)
    fields = []
    for column in columns:
        name = column["Field"]
        extra = (column.get("Extra") or "").lower()
        if name == OPERATOR_TABLES[table]["pk"] or "auto_increment" in extra:
            continue
        if name in ("created_at", "updated_at"):
            continue
        if name.endswith("_id") and name not in (
            "dept_id", "section_id", "coordinator_faculty_id"
        ):
            # Do not let the operator manually change unrelated foreign keys.
            continue
        col_type = (column.get("Type") or "varchar").lower()
        if "int" in col_type or "decimal" in col_type or "float" in col_type or "double" in col_type:
            input_type = "number"
        elif "date" in col_type and "datetime" not in col_type and "timestamp" not in col_type:
            input_type = "date"
        elif "datetime" in col_type or "timestamp" in col_type:
            input_type = "text"
        else:
            input_type = "text"
        fields.append({
            "name": name,
            "label": name.replace("_", " ").title(),
            "required": column.get("Null") == "NO" and column.get("Default") is None and "auto_increment" not in extra,
            "type": input_type,
            "column_type": col_type,
            "options": []
        })

    # Populate existing department/section references as dropdowns.
    connection = get_db_connection()
    if connection is None:
        raise RuntimeError("Database connection failed.")
    cursor = None
    try:
        cursor = connection.cursor(dictionary=True)
        for field in fields:
            if field["name"] == "dept_id":
                cursor.execute("SELECT dept_id AS id, dept_name AS label FROM departments ORDER BY dept_name")
                field["options"] = cursor.fetchall()
                field["type"] = "select"
            elif field["name"] == "section_id":
                cursor.execute("SELECT section_id AS id, section_name AS label FROM sections ORDER BY section_name")
                field["options"] = cursor.fetchall()
                field["type"] = "select"
            elif field["name"] == "coordinator_faculty_id":
                cursor.execute("SELECT faculty_id AS id, faculty_name AS label FROM faculty ORDER BY faculty_name")
                field["options"] = cursor.fetchall()
                field["type"] = "select"
    finally:
        if cursor:
            cursor.close()
        connection.close()
    return fields


def operator_get_record(table, record_id):
    if table not in OPERATOR_TABLES:
        abort(404)
    pk = OPERATOR_TABLES[table]["pk"]
    return fetch_one(f"SELECT * FROM `{table}` WHERE `{pk}` = %s", (record_id,))


def operator_records_page(table, search="", message=None, error=None):
    config = OPERATOR_TABLES[table]
    pk = config["pk"]
    columns = operator_table_columns(table)
    visible_columns = [c["Field"] for c in columns]
    # Keep the primary key visible, but hide long binary/blob fields.
    visible_columns = [c["Field"] for c in columns if "blob" not in (c.get("Type") or "").lower()]
    where = ""
    params = []
    searchable = [c["Field"] for c in columns if any(x in (c.get("Type") or "").lower() for x in ("char", "text"))]
    if search and searchable:
        where = " WHERE " + " OR ".join(f"CAST(`{name}` AS CHAR) LIKE %s" for name in searchable)
        params = [f"%{search}%"] * len(searchable)
    records = fetch_all(f"SELECT * FROM `{table}`{where} ORDER BY `{pk}` DESC", tuple(params))
    return render_template_string(r"""
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Operator | {{ title }}</title>
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;background:#f3f6fb;margin:0;padding:24px;color:#172033}
main{max-width:1400px;margin:auto;background:#fff;padding:24px;border-radius:14px;box-shadow:0 4px 18px #0000000c;overflow-x:auto}
h1{margin:18px 0}.top{display:flex;gap:10px;flex-wrap:wrap;align-items:center;justify-content:space-between}
a,.btn,button{display:inline-block;background:#2563eb;color:#fff;padding:9px 13px;border:0;border-radius:7px;text-decoration:none;cursor:pointer;font-size:14px}
.secondary{background:#475569}.danger{background:#dc2626}.search{display:flex;gap:8px;flex-wrap:wrap;margin:18px 0}
input{padding:10px;border:1px solid #cbd5e1;border-radius:7px;min-width:220px}table{width:100%;border-collapse:collapse;margin-top:18px;white-space:nowrap}
th,td{padding:11px;border-bottom:1px solid #e5e7eb;text-align:left}th{background:#eff6ff}td form{display:inline}
.notice{padding:12px;margin:12px 0;border-radius:7px;background:#ecfdf5;color:#065f46}.error{background:#fef2f2;color:#991b1b}
.actions{display:flex;gap:6px;align-items:center}
</style></head><body><main>
<div class="top"><a class="secondary" href="{{ url_for('operator_dashboard') }}">← Dashboard</a><a href="{{ add_url }}">+ Add {{ singular }}</a></div>
<div class="search" style="margin-top:12px"><a href="{{ url_for('operator_students') }}">Students</a><a href="{{ url_for('operator_faculty') }}">Faculty</a><a href="{{ url_for('operator_clubs') }}">Clubs</a><a href="{{ url_for('operator_departments') }}">Departments</a></div>
<h1>{{ title }}</h1>
{% if message %}<div class="notice">{{ message }}</div>{% endif %}{% if error %}<div class="notice error">{{ error }}</div>{% endif %}
<form class="search" method="get"><input name="q" value="{{ search }}" placeholder="Search records"><button type="submit">Search</button><a class="secondary" href="{{ list_url }}">Clear</a></form>
<p>Total records shown: {{ records|length }}</p>
<table><thead><tr>{% for col in visible_columns %}<th>{{ col.replace('_',' ').title() }}</th>{% endfor %}<th>Actions</th></tr></thead>
<tbody>{% for record in records %}<tr>{% for col in visible_columns %}<td>{{ record[col] if record[col] is not none else '' }}</td>{% endfor %}<td><div class="actions"><a href="{{ url_for(edit_endpoint, record_id=record[pk]) }}">Edit</a><form method="post" action="{{ url_for(delete_endpoint, record_id=record[pk]) }}" onsubmit="return confirm('Delete this record? This cannot be undone.');"><button class="danger" type="submit">Delete</button></form></div></td></tr>
{% else %}<tr><td colspan="{{ visible_columns|length + 1 }}">No records found.</td></tr>{% endfor %}</tbody></table>
</main></body></html>
""", title=config["title"], singular=config["label"], records=records,
        visible_columns=visible_columns, pk=pk, search=search,
        add_url=url_for(f"operator_{table}_add"), list_url=url_for(f"operator_{table}"),
        edit_endpoint=f"operator_{table}_edit", delete_endpoint=f"operator_{table}_delete",
        message=message, error=error)


def operator_record_form(table, record=None, error=None):
    config = OPERATOR_TABLES[table]
    fields = operator_form_fields(table)
    return render_template_string(r"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ heading }}</title><style>*{box-sizing:border-box}body{font-family:Arial;background:#f3f6fb;margin:0;padding:24px;color:#172033}
main{max-width:850px;margin:auto;background:white;padding:26px;border-radius:14px}h1{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}
label{display:block;font-weight:600;margin-bottom:6px}input,select{width:100%;padding:11px;border:1px solid #cbd5e1;border-radius:7px}button,a{display:inline-block;padding:10px 15px;border:0;border-radius:7px;background:#2563eb;color:white;text-decoration:none;cursor:pointer;margin-top:18px}.back{background:#475569}.error{background:#fef2f2;color:#991b1b;padding:12px;border-radius:7px}
</style></head><body><main><a class="back" href="{{ list_url }}">← Back to {{ singular }} Records</a><h1>{{ heading }}</h1>
{% if error %}<p class="error">{{ error }}</p>{% endif %}<form method="post"><div class="grid">
{% for field in fields %}<div><label for="{{ field.name }}">{{ field.label }}{% if field.required %} *{% endif %}</label>
{% if field.type == 'select' %}<select id="{{ field.name }}" name="{{ field.name }}" {% if field.required %}required{% endif %}><option value="">Select {{ field.label }}</option>{% for option in field.options %}<option value="{{ option.id }}" {% if record and record[field.name]|string == option.id|string %}selected{% endif %}>{{ option.label }}</option>{% endfor %}</select>
{% else %}<input id="{{ field.name }}" name="{{ field.name }}" type="{{ field.type }}" value="{{ record[field.name] if record and record[field.name] is not none else '' }}" {% if field.required %}required{% endif %} {% if field.type == 'number' and ('int' in field.column_type) %}step="1"{% elif field.type == 'number' %}step="any"{% endif %}>
{% endif %}</div>{% endfor %}</div><button type="submit">Save {{ singular }}</button></form></main></body></html>
""", heading=("Edit " if record else "Add ") + config["label"], fields=fields,
        record=record, error=error, list_url=url_for(f"operator_{table}"), singular=config["label"])


def operator_save_record(table, record_id=None):
    if table not in OPERATOR_TABLES:
        abort(404)
    fields = operator_form_fields(table)
    values = {}
    for field in fields:
        value = request.form.get(field["name"], "").strip()
        if value == "":
            if field["required"]:
                return None, f"{field['label']} is required."
            continue
        values[field["name"]] = value
    if not values:
        return None, "Please enter the record details."

    # Only schema-derived field names are used in the SQL statement.
    allowed = {field["name"] for field in fields}
    if not set(values).issubset(allowed):
        abort(400)
    connection = get_db_connection()
    if connection is None:
        raise RuntimeError("Database connection failed.")
    cursor = None
    try:
        cursor = connection.cursor()
        if record_id is None:
            names = list(values.keys())
            sql = f"INSERT INTO `{table}` ({', '.join(f'`{name}`' for name in names)}) VALUES ({', '.join(['%s'] * len(names))})"
            cursor.execute(sql, tuple(values[name] for name in names))
        else:
            pk = OPERATOR_TABLES[table]["pk"]
            assignments = ", ".join(f"`{name}` = %s" for name in values)
            cursor.execute(f"UPDATE `{table}` SET {assignments} WHERE `{pk}` = %s", tuple(values[name] for name in values) + (record_id,))
            if cursor.rowcount == 0:
                connection.rollback()
                return None, "Record not found or no details were changed."
        connection.commit()
        return True, None
    except Exception as exc:
        connection.rollback()
        app.logger.exception("Operator record save failed for %s", table)
        return None, str(exc)
    finally:
        if cursor:
            cursor.close()
        connection.close()


# ==========================================
# OPERATOR - STUDENT CRUD
# ==========================================

@app.route("/operator/students")
@login_required
@role_required("OPERATOR")
def operator_students():
    return operator_records_page("students", request.args.get("q", "").strip(),
                                 request.args.get("message"), request.args.get("error"))


@app.route("/operator/students/add", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_students_add():
    if request.method == "POST":
        success, error = operator_save_record("students")
        if success:
            return redirect(url_for("operator_students", message="Student added successfully."))
        return operator_record_form("students", error=error)
    return operator_record_form("students")


@app.route("/operator/students/edit/<int:record_id>", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_students_edit(record_id):
    record = operator_get_record("students", record_id)
    if not record:
        abort(404)
    if request.method == "POST":
        success, error = operator_save_record("students", record_id)
        if success:
            return redirect(url_for("operator_students", message="Student updated successfully."))
        return operator_record_form("students", record=record, error=error)
    return operator_record_form("students", record=record)


@app.route("/operator/students/delete/<int:record_id>", methods=["POST"])
@login_required
@role_required("OPERATOR")
def operator_students_delete(record_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM students WHERE student_id = %s", (record_id,))
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for("operator_students", message="Student deleted successfully."))
    except Exception:
        try:
            connection.rollback()
            cursor.close()
            connection.close()
        except Exception:
            pass
        app.logger.exception("Operator student deletion failed")
        return redirect(url_for("operator_students", error="Could not delete this student. This record may be linked to a login, event, club, or other record. Remove or reassign linked records first."))


# ==========================================
# OPERATOR - FACULTY CRUD
# ==========================================

@app.route("/operator/faculty")
@login_required
@role_required("OPERATOR")
def operator_faculty():
    return operator_records_page("faculty", request.args.get("q", "").strip(),
                                 request.args.get("message"), request.args.get("error"))


@app.route("/operator/faculty/add", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_faculty_add():
    if request.method == "POST":
        success, error = operator_save_record("faculty")
        if success:
            return redirect(url_for("operator_faculty", message="Faculty record added successfully."))
        return operator_record_form("faculty", error=error)
    return operator_record_form("faculty")


@app.route("/operator/faculty/edit/<int:record_id>", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_faculty_edit(record_id):
    record = operator_get_record("faculty", record_id)
    if not record:
        abort(404)
    if request.method == "POST":
        success, error = operator_save_record("faculty", record_id)
        if success:
            return redirect(url_for("operator_faculty", message="Faculty record updated successfully."))
        return operator_record_form("faculty", record=record, error=error)
    return operator_record_form("faculty", record=record)


@app.route("/operator/faculty/delete/<int:record_id>", methods=["POST"])
@login_required
@role_required("OPERATOR")
def operator_faculty_delete(record_id):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("DELETE FROM faculty WHERE faculty_id = %s", (record_id,))
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for("operator_faculty", message="Faculty record deleted successfully."))
    except Exception:
        try:
            connection.rollback()
            cursor.close()
            connection.close()
        except Exception:
            pass
        app.logger.exception("Operator faculty deletion failed")
        return redirect(url_for("operator_faculty", error="Could not delete this faculty record. It may be linked to a login, announcement, or other record. Remove or reassign linked records first."))




# ==========================================
# OPERATOR - CLUB CRUD
# ==========================================

@app.route("/operator/clubs")
@login_required
@role_required("OPERATOR")
def operator_clubs():
    return operator_records_page("clubs", request.args.get("q", "").strip(),
                                 request.args.get("message"), request.args.get("error"))


@app.route("/operator/clubs/add", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_clubs_add():
    if request.method == "POST":
        success, error = operator_save_record("clubs")
        if success:
            return redirect(url_for("operator_clubs", message="Club added successfully."))
        return operator_record_form("clubs", error=error)
    return operator_record_form("clubs")


@app.route("/operator/clubs/edit/<int:record_id>", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_clubs_edit(record_id):
    record = operator_get_record("clubs", record_id)
    if not record:
        abort(404)
    if request.method == "POST":
        success, error = operator_save_record("clubs", record_id)
        if success:
            return redirect(url_for("operator_clubs", message="Club updated successfully."))
        return operator_record_form("clubs", record=record, error=error)
    return operator_record_form("clubs", record=record)


@app.route("/operator/clubs/delete/<int:record_id>", methods=["POST"])
@login_required
@role_required("OPERATOR")
def operator_clubs_delete(record_id):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection is None:
            raise RuntimeError("Database connection failed.")
        cursor = connection.cursor()
        cursor.execute("DELETE FROM clubs WHERE club_id = %s", (record_id,))
        if cursor.rowcount == 0:
            connection.rollback()
            return redirect(url_for("operator_clubs", error="Club record was not found."))
        connection.commit()
        return redirect(url_for("operator_clubs", message="Club deleted successfully."))
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Operator club deletion failed")
        return redirect(url_for("operator_clubs", error="Could not delete this club. It may have student memberships or other linked records."))
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ==========================================
# OPERATOR - DEPARTMENT CRUD
# ==========================================

@app.route("/operator/departments")
@login_required
@role_required("OPERATOR")
def operator_departments():
    return operator_records_page("departments", request.args.get("q", "").strip(),
                                 request.args.get("message"), request.args.get("error"))


@app.route("/operator/departments/add", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_departments_add():
    if request.method == "POST":
        success, error = operator_save_record("departments")
        if success:
            return redirect(url_for("operator_departments", message="Department added successfully."))
        return operator_record_form("departments", error=error)
    return operator_record_form("departments")


@app.route("/operator/departments/edit/<int:record_id>", methods=["GET", "POST"])
@login_required
@role_required("OPERATOR")
def operator_departments_edit(record_id):
    record = operator_get_record("departments", record_id)
    if not record:
        abort(404)
    if request.method == "POST":
        success, error = operator_save_record("departments", record_id)
        if success:
            return redirect(url_for("operator_departments", message="Department updated successfully."))
        return operator_record_form("departments", record=record, error=error)
    return operator_record_form("departments", record=record)


@app.route("/operator/departments/delete/<int:record_id>", methods=["POST"])
@login_required
@role_required("OPERATOR")
def operator_departments_delete(record_id):
    connection = None
    cursor = None
    try:
        connection = get_db_connection()
        if connection is None:
            raise RuntimeError("Database connection failed.")
        cursor = connection.cursor()
        cursor.execute("DELETE FROM departments WHERE dept_id = %s", (record_id,))
        if cursor.rowcount == 0:
            connection.rollback()
            return redirect(url_for("operator_departments", error="Department record was not found."))
        connection.commit()
        return redirect(url_for("operator_departments", message="Department deleted successfully."))
    except Exception:
        if connection:
            connection.rollback()
        app.logger.exception("Operator department deletion failed")
        return redirect(url_for("operator_departments", error="Could not delete this department. It may be linked to students, faculty, clubs, or other records."))
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# ==========================================
# LOGOUT
# ==========================================

@app.route("/logout")
def logout():

    session.clear()
    return redirect(url_for("home"))


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(403)
def forbidden(error):

    return render_template(
        "error.html",
        code=403,
        message="You do not have permission to access this page."
    ), 403


@app.errorhandler(404)
def not_found(error):

    return render_template(
        "error.html",
        code=404,
        message="The requested page or record was not found."
    ), 404


@app.errorhandler(500)
def server_error(error):

    app.logger.error("Server error: %s", error)

    return render_template(
        "error.html",
        code=500,
        message="Something went wrong. Please check the Flask terminal for the detailed error."
    ), 500


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        debug=os.getenv(
            "FLASK_DEBUG", "False"
        ).lower() == "true",
        host="127.0.0.1",
        port=5000
    )
