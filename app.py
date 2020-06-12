from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import error, login_required, errorhandler

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


@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit():
    """Submit notes to database"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not (request.form.get("textbox")):
            return error("must provide text", 400)
        
        text = request.form.get("textbox")

        if len(text) > 1000:
            return error("text too long", 403)

        db.execute("INSERT INTO notes (user_id, text) VALUES(:user_id, :text)",
                   user_id=session["user_id"], text=text)

        return redirect("/")
    
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("submit.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Sign up user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return error("must provide username", 400)

        # Ensure password was submitted
        if not request.form.get("password"):
            return error("must provide password", 400)

        # Ensure confirmation password matches password
        elif request.form.get("password") != request.form.get("confirmation"):
            return error("confirmation password wrong", 403)

        # Ensure that username is not already taken
        rows = db.execute("SELECT * FROM users WHERE username = :username", 
                          username=request.form.get("username"))
        if len(rows) != 0:
            return error("username already taken", 409)

        # Insert username and hashed password into database
        db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                   username=request.form.get("username"), 
                   hash=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8))

        # Ensure user is in database
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["username"]

        # Redirect user to home page
        flash(f'User {request.form.get("username")} successfully registered')
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
            return error("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return error("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return error("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Manage user's profile"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # User wants to change their password
        if request.form.get("submit") == "change":

            # Ensure old password was submitted
            if not request.form.get("oldPassword"):
                return error("must provide old password", 400)
            
            # Ensure new password was submitted
            if not request.form.get("newPassword"):
                return error("must provide new password", 400)
            
            # Ensure confirmation password matches new password
            if request.form.get("newPassword") != request.form.get("confirmation"):
                return error("confirmation password wrong", 403)
            
            # Ensure new password is not the same as old password
            if request.form.get("oldPassword") == request.form.get("newPassword"):
                return error("new password must be different from old password", 409)

            # Query database for user id
            rows = db.execute("SELECT * FROM users WHERE id = :id",
                            id=session["user_id"])

            # Ensure user exists and password is correct
            if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("oldPassword")):
                return error("invalid password", 403)

            # Update password
            db.execute("UPDATE users SET hash = :hash WHERE id = :id",
                       hash=generate_password_hash(request.form.get("newPassword"), method='pbkdf2:sha256', salt_length=8),
                       id=session["user_id"])

            # Redirect user to home page
            flash('Password successfully changed')
            return redirect("/")

        # User wants to delete their profile
        else:

            # Ensure user confirmed deletion
            if not request.form.get("confirm"):
                return error("must confirm deletion", 403)

            # Redirect user to deletion page
            return redirect("/delete")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("profile.html")


@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    """Delete user's profile from database"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # User is sure they want to delete their profile
        if request.form.get("submit") == "yes":

            # Delete user's shares from database
            db.execute("DELETE FROM shares JOIN notes ON shares.note_id = notes.id JOIN users ON notes.user_id = users.id WHERE id = :id",
                       id=session["user_id"])

            # Delete user's notes from database
            db.execute("DELETE FROM notes JOIN users ON notes.user_id = users.id WHERE id = :id",
                       id=session["user_id"])

            # Delete profile from database
            db.execute("DELETE FROM users WHERE id = :id",
                    id=session["user_id"])

            # Log out user
            return redirect("/logout")
        
        # User doesn't want to delete their profile
        else:
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("delete.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


# Check for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
