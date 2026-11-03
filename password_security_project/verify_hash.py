
import sqlite3
from pathlib import Path
from getpass import getpass
from werkzeug.security import check_password_hash

db_path = Path(__file__).with_name("password_security.db")
connection = sqlite3.connect(db_path)
cursor = connection.cursor()

username = input("Enter your test username: ").strip()

cursor.execute(
    "SELECT password_hash FROM users WHERE username = ?",
    (username,)
)
record = cursor.fetchone()

if record is None:
    print("User not found. Check the username.")
else:
    stored_hash = record[0]

    # Check the hashing format without displaying the hash
    if stored_hash.startswith("scrypt:"):
        print("Password hashing format: scrypt")
        print("Plaintext password storage: Not detected")

        password = getpass("Enter the test account password (hidden): ")

        if check_password_hash(stored_hash, password):
            print("Password verification: PASSED")
        else:
            print("Password verification: FAILED")
    else:
        print("Unexpected password hash format. Investigate.")

connection.close()
