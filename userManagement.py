import sqlite3 as sql
import bcrypt
import pyotp


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
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        totp_secret = pyotp.random_base32()
        cur.execute(
            "INSERT INTO users (email,password,totp_secret) VALUES (?,?,?)",
            (email, hashed.decode("utf-8"), totp_secret),
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
    cur.execute(
        "SELECT email,password,totp_secret FROM users WHERE email = ?", (email,)
    )
    row = cur.fetchone()
    con.close()

    if row is None:
        return (False, "Email isn't registered", None)

    stored_password = row[1]
    stored_secret = row[2]
    if bcrypt.checkpw(password.encode("utf-8"), stored_password.encode("utf-8")):
        return (True, "Signed in", stored_secret)
    else:
        return (False, "Wrong password", None)
