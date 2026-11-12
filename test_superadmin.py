from db import get_db_connection
from werkzeug.security import check_password_hash

connection = get_db_connection()
cursor = connection.cursor(dictionary=True)

cursor.execute(
    "SELECT password_hash FROM user_accounts WHERE username = %s",
    ("superadmin",)
)

account = cursor.fetchone()

if account:
    password = "Admin@12345"

    if check_password_hash(account["password_hash"], password):
        print("PASSWORD MATCHED")
    else:
        print("PASSWORD DOES NOT MATCH")
else:
    print("ACCOUNT NOT FOUND")

cursor.close()
connection.close()