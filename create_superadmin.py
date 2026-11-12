
from werkzeug.security import generate_password_hash
from db import get_db_connection

USERNAME = "superadmin"
PASSWORD = "Admin@12345"

def create_superadmin():

    connection = get_db_connection()

    if connection is None:
        print("Database connection failed.")
        return

    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT user_id FROM user_accounts WHERE username = %s",
            (USERNAME,)
        )

        existing = cursor.fetchone()

        if existing:
            print("Super Admin account already exists.")
            print("User ID:", existing["user_id"])
            return

        password_hash = generate_password_hash(PASSWORD)

        cursor.execute("""
            INSERT INTO user_accounts
            (username, password_hash, role, is_active)
            VALUES (%s, %s, %s, %s)
        """, (USERNAME, password_hash, "ADMIN", 1))

        connection.commit()

        print("Super Admin account created successfully!")
        print("Username:", USERNAME)
        print("Password:", PASSWORD)
        print("Role: SUPER_ADMIN")

    except Exception as error:
        connection.rollback()
        print("Error:", error)

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    create_superadmin()
