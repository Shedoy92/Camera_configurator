import sqlite3

db = sqlite3.connect('awesome.db')
cursor = db.cursor()
username = input("Enter username: ")
password = input("Enter password: ")
user_group = input("Enter role: ")

cursor.execute("INSERT INTO users (username, password, user_group) VALUES (?, ?, ?)", (username, password, user_group))
db.commit()
db.close()
