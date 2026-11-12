
import csv
import secrets
from pathlib import Path

from werkzeug.security import generate_password_hash
from db import get_db_connection


def create_accounts():

    connection = get_db_connection()

    if connection is None:
        print("Database connection failed!")
        return

    cursor = connection.cursor(dictionary=True)

    credentials = []
    created = 0

    try:
        # Get existing usernames and linked IDs
        cursor.execute("""
            SELECT username, student_id, faculty_id
            FROM user_accounts
        """)

        existing = cursor.fetchall()

        usernames = {x["username"] for x in existing}
        student_ids = {
            x["student_id"] for x in existing
            if x["student_id"] is not None
        }
        faculty_ids = {
            x["faculty_id"] for x in existing
            if x["faculty_id"] is not None
        }

        def add_account(username, role, student_id=None, faculty_id=None):

            nonlocal created

            if username in usernames:
                print("Already exists:", username)
                return

            if student_id is not None and student_id in student_ids:
                return

            if faculty_id is not None and faculty_id in faculty_ids:
                return

            password = secrets.token_urlsafe(12)
            password_hash = generate_password_hash(password)

            cursor.execute("""
                INSERT INTO user_accounts
                (username, password_hash, role, student_id, faculty_id)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                username,
                password_hash,
                role,
                student_id,
                faculty_id
            ))

            credentials.append({
                "username": username,
                "password": password,
                "role": role
            })

            usernames.add(username)

            if student_id is not None:
                student_ids.add(student_id)

            if faculty_id is not None:
                faculty_ids.add(faculty_id)

            created += 1

            print("Created:", username, "-", role)

        # 1. Student accounts
        cursor.execute("""
            SELECT student_id, roll_number
            FROM students
        """)

        for student in cursor.fetchall():

            add_account(
                student["roll_number"],
                "STUDENT",
                student_id=student["student_id"]
            )

        # 2. Faculty and HOD accounts
        cursor.execute("""
            SELECT
                f.faculty_id,
                f.faculty_code,
                f.faculty_no,
                d.dept_code
            FROM faculty f
            JOIN departments d
                ON f.dept_id = d.dept_id
        """)

        for faculty in cursor.fetchall():

            if faculty["faculty_no"] == 1:

                username = "hod_" + faculty["dept_code"].lower()

                add_account(
                    username,
                    "HOD",
                    faculty_id=faculty["faculty_id"]
                )

            else:

                add_account(
                    faculty["faculty_code"].lower(),
                    "FACULTY",
                    faculty_id=faculty["faculty_id"]
                )

        # 3. Super Admin account
        add_account(
            "campusadmin",
            "ADMIN"
        )

        # 4. Operator account
        add_account(
            "campusoperator",
            "OPERATOR"
        )

        connection.commit()

        # Save newly generated credentials without overwriting old ones
        if credentials:

            file_path = (
                Path(__file__).resolve().parent /
                "initial_credentials.csv"
            )

            file_exists = file_path.exists()
            write_header = (
                not file_exists or file_path.stat().st_size == 0
            )

            with open(
                file_path,
                "a",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=["username", "password", "role"]
                )

                if write_header:
                    writer.writeheader()

                writer.writerows(credentials)

            print("Credentials saved to:", file_path)

        print("--------------------------------")
        print("ACCOUNT CREATION COMPLETED")
        print("--------------------------------")
        print("New accounts created:", created)
        print("Credentials generated:", len(credentials))
        print("Check initial_credentials.csv")
        print("--------------------------------")

    except Exception as error:

        connection.rollback()
        print("Account creation failed:", error)

    finally:

        cursor.close()
        connection.close()


if __name__ == "__main__":
    create_accounts()
