import sqlite3
from werkzeug.security import generate_password_hash

db = sqlite3.connect('awesome.db')
cursor = db.cursor()
username = input("Enter username: ")
password = input("Enter password: ")
user_group = input("Enter role: ")

hashed_password=generate_password_hash(password)
cursor.execute("INSERT INTO users (username, password, user_group) VALUES (?, ?, ?)", (username, hashed_password, user_group))
db.commit()
db.close()
