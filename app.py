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
def index():
    """Show index of user's notes"""

    # Query database for user's notes
    rows = db.execute("SELECT id, author, text, timestamp FROM notes WHERE id IN (SELECT note_id FROM participants WHERE user_id = :id) ORDER BY timestamp DESC",
                      id=session["user_id"])

    # Render page with user's notes
    return render_template("index.html", rows=rows)


@app.route("/submit", methods=["GET", "POST"])
@login_required
def submit():
    """Submit notes to database"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure text was submitted
        if not (request.form.get("textbox")):
            return error("must provide text", 400)
        text = request.form.get("textbox")

        # Ensure text isn't too short or too long
        if len(text) <= 0 or len(text) > 1000:
            return error("text length invalid", 403)

        # Insert note into database
        note_id = db.execute("INSERT INTO notes (author, text, timestamp) VALUES(:user_name, :text, datetime('now', '+2 hours'))",
                             user_name=session["user_name"], text=text)

        if not note_id:
            return error("failed to save note to database", 503)

        # Give access to user
        if not db.execute("INSERT INTO participants (note_id, user_id) VALUES (:note_id, :user_id)",
                          note_id=note_id, user_id=session["user_id"]):
            return error("failed to save access to note", 503)

        # User wants to share note with other profiles
        if request.form.get("share"):

            # Call share function
            count = share(request.form.get("share"), note_id)

            # Notify how many profiles note was shared with
            flash(f'Note shared with {count} other profiles')

        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("submit.html")


@app.route("/deletenote")
@login_required
def deletenote():
    """Delete note"""

    # Ensure note ID was submitted
    if not request.args.get("note_id"):
        return error("must provide note ID", 400)

    note_id = int(request.args.get("note_id"))

    # Ensure note exists
    rows = db.execute("SELECT * FROM participants WHERE note_id = :note_id",
                      note_id=note_id)

    if len(rows) != 1:
        return error("note not found", 404)

    # Ensure user has access to note
    hasAccess = False
    for row in rows:
        if row["user_id"] == session["user_id"]:
            hasAccess = True
            break

    if hasAccess == False:
        return error("cannot delete note without having access to it", 403)

    # Delete access to note
    if db.execute("DELETE FROM participants WHERE note_id = :note_id AND user_id = :user_id",
                  note_id=note_id, user_id=session["user_id"]) == 0:
        return error("failed to delete access to note", 503)

    # If user is only profile with access to note, delete note
    if len(rows) == 1:
        if db.execute("DELETE FROM notes WHERE id = :note_id",
                      note_id=note_id) == 0:
            return error("failed to delete note", 503)

    # Redirect user to homepage
    return redirect("/")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Sign up user"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return error("must provide username", 400)

        # Ensure username is not too short or too long
        if len(request.form.get("username")) < 4 or len(request.form.get("username")) > 20:
            return error("username length invalid", 403)

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
        if not db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
                          username=request.form.get("username"),
                          hash=generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)):
            return error("failed to save profile to database", 503)

        # Ensure user is in database
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["username"]

        # Redirect user to home page
        flash(f'User "{request.form.get("username")}" successfully registered')
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
            if db.execute("UPDATE users SET hash = :hash WHERE id = :id",
                           hash=generate_password_hash(request.form.get("newPassword"), method='pbkdf2:sha256', salt_length=8),
                           id=session["user_id"]) == 0:
                return error("failed to update password", 503)

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
        if request.form.get("confirm") == "yes":

            # Delete access to notes authored by profile
            db.execute("DELETE FROM participants WHERE note_id IN (SELECT id FROM notes WHERE author = :user_name)",
                       user_name=session["user_name"])

            # Delete notes authored by profile
            db.execute("DELETE FROM notes WHERE author = :user_name",
                       user_name=session["user_name"])

            # Delete profile
            if db.execute("DELETE FROM users WHERE id = :id",
                           id=session["user_id"]) == 0:
                return error("failed to delete profile", 503)

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


def share(usernames, note_id):
    """Share note with other users"""

    # Ensure all arguments was submitted
    if not usernames:
        return 0

    if not note_id:
        return 0

    # Seperate usernames by space
    usernames = usernames.split(sep=" ")

    # Iterate over usernames
    count = 0
    for username in usernames:

        # Ensure username has valid length
        if len(username) > 4 or len(username) < 20:
            continue

        # Ensure username is not current user's username
        if username == session["user_name"]:
            continue

        # Ensure profile actually exists
        rows = db.execute("SELECT * FROM users WHERE username = :username")

        if len(rows) != 1:
            continue

        # Save user ID
        user_id = rows[0]["id"]

        # Ensure profile doesn't already have access to note
        rows = db.execute("SELECT * FROM participants WHERE note_id = :note_id AND user_id = :user_id",
                                note_id=note_id, user_id=user_id)

        if len(rows) != 0:
            continue

        # Share note with profile
        if not db.execute("INSERT INTO participants (note_id, user_id) VALUES (:note_id, :user_id)",
                    note_id=note_id, user_id=user_id):
            return error("failed to share note with user", 503)

        # Count how many profiles note was shared with
        count += 1

    # Return that count
    return count


# Check for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
