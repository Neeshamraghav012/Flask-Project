import os
import sqlite3, secrets
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

app = Flask(__name__)

secret = secrets.token_urlsafe(32)
app.secret_key = secret

# Basic app configuration.
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")
db.execute("CREATE TABLE IF NOT EXISTS users (id integer primary key autoincrement not null, username VARCHAR(255)NOT NULL UNIQUE, hash TEXT NOT NULL)")



@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    if request.method == "POST":

        if not request.form.get("username"): # we use not when converting false to true
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("login.html")



@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    if request.method == "GET":
        rows = db.execute("select username from users where id = (?)", session["user_id"])
        if len(rows) == 1:
            return render_template("index.html", rows=rows)
        else:
            return apology("I don't love you!")

    else:
        return apology("Error")


@app.route("/logout")
def logout():

    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        name = request.form.get('username')

        row_name = db.execute("SELECT * FROM users WHERE username = :username", username = name)

        if not name or len(row_name) != 0:
            return apology("Username already taken! ")

        _pass = request.form.get('password')
        pass_conf = request.form.get('confirmation')

        if _pass != pass_conf:
            return apology("Password didn't match ")

        else:
            password = generate_password_hash(_pass)

            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, password)

        return redirect("/")

    else:
        return render_template("register.html")


def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
