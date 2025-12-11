import sqlite3 as sql
import bcrypt


### example
def getUsers():
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM id7-tusers")
    con.close()
    return cur


def insertUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email,password) VALUES (?,?)", (email, password)
        )
        con.commit()
        con.close()
        return (True, "Inserted")
    except sql.IntegrityError:
        con.close()
        return (False, "Email already exists")


def verifyUser(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT email,password FROM users WHERE email = ?", (email,))
    row = cur.fetchone()
    con.close()
    if row == None:
        return (False, "Email isn't registered")
    else:
        stored_password = row[1]
        if stored_password == password:
            return (True, "Signed in")
        else:
            return (False, "Wrong password")
