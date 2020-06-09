from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, errorhandler

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///final.db")

@app.route("/")
@login_required
def hello():
    """Default start page"""
    return render_template("hello.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Sign up user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html", code=400, message="Must provide username"), 400

        # Ensure that username is not already taken
        rows = db.execute("SELECT * FROM users WHERE username = :username", 
                          username=request.form.get("username"))
        if len(rows) != 0:
            return render_template("error.html", code=409, message="Username already taken"), 409

        # Ensure password was submitted
        if not request.form.get("password"):
            return render_template("error.html", code=400, message="must provide password"), 400

        # Ensure confirmation password matches password
        elif request.form.get("password") != request.form.get("confirmation"):
            return render_template("error.html", code=403, message="confirmation password wrong"), 403

        # Insert username and hashed password into database
        db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                   username=request.form.get("username"), 
                   hash=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        # Ensure user is in database
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to homepage
        flash(f'User {request.form.get("username")} successfully registered!')
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html", code=400, message="Must provide username"), 400

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("error.html", code=400, message="Must provide password"), 400

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("error.html", code=403, message="invalid username and/or password"), 403

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
