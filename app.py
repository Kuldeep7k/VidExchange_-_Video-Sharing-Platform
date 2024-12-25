import uuid
import os

from flask import Flask, flash, redirect, render_template, request, session, g, url_for, send_file, jsonify
from flask_session import Session
from flask import send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from helpers import error_page, login_required
import sqlite3

import re

app = Flask(__name__)
DATABASE = 'database.db'

UPLOAD_FOLDER = 'uploads' 
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv'}


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


def generate_public_video_id():
    return str(uuid.uuid4())  # Generates a unique identifier


def is_valid_mail(email):
    if not email:
        return False

    mail_regex = r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+'
    return bool(re.match(mail_regex, email))


def is_valid_password(password):
    if not password:
        return False

    password_regex = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')
    return bool(password_regex.match(password))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    session.clear()  # Clear any existing session

    if request.method == "POST":
        # Get form data
        userName = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Ensure username was submitted
        if not userName:
            return error_page("Must provide userName.", 400)

        # Validate email
        if not is_valid_mail(email):
            return error_page("Invalid email. Please provide a valid email.", 400)

        # Ensure passwords match
        if confirm_password != password:
            return error_page("Passwords do not match.", 400)

        # Validate password strength
        if not is_valid_password(password):
            return error_page("Password must be at least 8 characters long, contain letters, numbers, and special characters.", 400)

        # Hash the password
        hashed_password = generate_password_hash(password)

        # Get database connection and create a cursor
        db = get_db()
        cursor = db.cursor()

        # Check if the username already exists
        check_username = cursor.execute(
            "SELECT * FROM users WHERE username = ?", (userName,))
        existing_user = check_username.fetchone()  # Fetch a single row

        if existing_user:
            return error_page("Username is already taken.", 400)

        # Insert the new user
        cursor.execute("INSERT INTO users (username, email, hash) VALUES (?, ?, ?)",
                       (userName, email, hashed_password))
        db.commit()  # Commit the changes to the database

        flash("Account Created Successfully!")

        # Retrieve the user ID and log in the user
        user = cursor.execute(
            "SELECT id FROM users WHERE username = ?", (userName,))
        user_registered = user.fetchone()

        if user_registered:
            # Store the user ID in the session
            session["user_id"] = user_registered["id"]
        else:
            return error_page("Error retrieving user ID.", 500)

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        # Ensure email was submitted
        email = request.form.get("email")
        password = request.form.get("password")

        if not email:
            return error_page("Must provide email.", 403)

        if not password:
            return error_page("Must provide password.", 403)

        # Query database for the user
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        # Ensure user exists and password is correct
        if not user:
            return error_page("Invalid email and/or password.", 403)

        if not check_password_hash(user["hash"], password):
            return error_page("Invalid email and/or password.", 403)

        # Remember which user has logged in
        session["user_id"] = user["id"]

        flash("Login successfully!")

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/")
@login_required
def index():
    db = get_db()
    cursor = db.cursor()
    rows = cursor.execute(
        "SELECT * FROM videos WHERE user_id = ? ORDER BY upload_date DESC LIMIT 2", (
            session["user_id"],)
    ).fetchall()

    return render_template("index.html", data=rows)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload_video():
    if 'video_file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['video_file']

    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file and allowed_file(file.filename):
        # Secure the filename
        filename = secure_filename(file.filename)

        # Generate a unique custom link (implement this)
        public_video_id = generate_public_video_id()

        # Save the file
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)

        # Save video details in the database
        user_id = session.get("user_id")  # Get the current user's ID
        title = filename  # You may want to provide a title input field as well
        # Use an empty string if description is not provided
        description = request.form.get("description") or "NA"

        description = description[:50]  # Trim to a maximum of 50 characters

        save_video_to_db(user_id, title, description, public_video_id)

        flash('Video uploaded successfully!')
        return redirect("/myvideos")  # Redirect to a relevant page

    return error_page("Invalid file type. Please upload a video file.", 403)


def save_video_to_db(user_id, title, description, public_video_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO videos (user_id, title, description, public_video_id) VALUES (?, ?, ?, ?)",
        (user_id, title, description, public_video_id)
    )
    db.commit()


@app.route("/myvideos", methods=['GET'])
@login_required
def myvideos():
    """Show portfolio of videos"""
    db = get_db()
    cursor = db.cursor()
    rows = cursor.execute(
        "SELECT * FROM videos WHERE user_id = ? ORDER BY upload_date DESC", (
            session["user_id"],)
    ).fetchall()

    for row in rows:
        print(f"Video ID: {row['id']}, Title: {
              row['title']}, Description: {row['description']}")

    return render_template("myvideos.html", data=rows)


@app.route('/uploads/<path:filename>')
def serve_video(filename):
    return send_from_directory('uploads', filename)


@app.route("/play", methods=["POST", "GET"])
def play_video():
    if request.method == "POST":
        link = request.form.get("link")
        db = get_db()
        cursor = db.cursor()

        # Fetch video title using custom link
        video_info = cursor.execute(
            "SELECT * FROM videos WHERE public_video_id = ?", (link,)).fetchone()
        if video_info is None:
            return error_page("Link video not available. Ask for a new link.", 403)

        # Ensure the title is correctly assigned with the extension
        video_title = video_info["title"]

        title = video_info["title"]

        # Assuming title has a file extension
        return render_template("play_video.html",  videoTitle=video_title[:-4], videoData=video_info, title=title)
    else:
        return render_template("play_video.html")


@app.route("/delete", methods=["POST"])
def delete_video():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("DELETE FROM videos WHERE public_video_id = ?",
                   (request.form.get("link"),))

    db.commit()
    flash("Video deleted successfully!")
    return redirect("/myvideos")


@app.route("/share", methods=["POST"])
def share_video():
    if request.method == "POST":
        link = request.form.get("link")
        db = get_db()
        cursor = db.cursor()

        # Generate a new custom link
        new_link = generate_public_video_id()

        # Check current visibility
        current_access = cursor.execute(
            "SELECT visibility FROM videos WHERE public_video_id = ?", (link,)).fetchone()

        if current_access:
            # Toggle visibility
            new_visibility = "public" if current_access[0] == "private" else "private"

            # Update video with new link and visibility
            cursor.execute("UPDATE videos SET public_video_id = ?, visibility = ? WHERE public_video_id = ?",
                           (new_link, new_visibility, link))

            db.commit()
            flash(f"Video Access updated to {new_visibility}!")
        else:
            return error_page("Something goes wrong.. Please try Again", 403)

        return redirect("/myvideos")


@app.route("/profile", methods=["GET"])
def profile():
    # Query database for the user
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    user = cursor.fetchone()

    return render_template("profile.html", user_data=user)


@app.route("/changepassword", methods=["POST"])
@login_required
def changepassword():
    """Change user's password"""
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not current_password or not new_password or not confirm_password:
            return error_page("Must provide old password, new password, and confirm new password", 403)

        if new_password != confirm_password:
            return error_page("New passwords do not match", 403)

        if len(new_password) < 8:
            return error_page("New password must be at least 8 characters long", 403)

        # Get the user's current hashed password
        db = get_db()
        cursor = db.cursor()
        old_password = cursor.execute(
            "SELECT hash FROM users WHERE id = ?", (session["user_id"],)).fetchone()

        if not old_password or not check_password_hash(old_password["hash"], current_password):
            return error_page("Invalid Current Password", 403)

        # Hash the new password and update in the database
        new_hash = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET hash = ? WHERE id = ?",
                       (new_hash, session["user_id"]))
        db.commit()

        flash("Password has been changed!")
        return redirect("/profile")


@app.route("/changeusername", methods=["POST"])
@login_required
def changeusername():
    """Change UserName"""
    if request.method == "POST":
        current_username = request.form.get("currentUsername")
        new_username = request.form.get("newUsername")

        db = get_db()
        cursor = db.cursor()
        old_username = cursor.execute(
            "SELECT username FROM users WHERE username = ?", (current_username,)).fetchone()

        if old_username is None:
            return error_page("Invalid Current Username", 403)

        cursor.execute("UPDATE users SET username = ? WHERE id = ?",
                       (new_username, session["user_id"]))

        db.commit()

        flash("UserName has been changed!")

        return redirect("/profile")


@app.route('/download/<path:filename>')
def download_file(filename):
    # Ensure you use the full path to the uploads directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route("/download", methods=["POST"])
@login_required
def download_video():
    if request.method == "POST":
        link = request.form.get("link")
        db = get_db()
        cursor = db.cursor()

        # Fetch the video details using the custom link
        video_info = cursor.execute(
            "SELECT title FROM videos WHERE public_video_id = ?", (link,)).fetchone()

        if video_info is None:
            return error_page("Video not available. Ask for a new link.", 403)

        # Use the title to create the filename (ensure to add the file extension)
        # Ensure this has the correct file extension
        filename = video_info['title']

        # Redirect to the download route
        return redirect(url_for('download_file', filename=filename))


@app.route("/downloadPermission", methods=["POST"])
@login_required
def downloadPermission():
    public_video_id = request.form.get("link")
    db = get_db()
    cursor = db.cursor()

    if public_video_id:
        # Check if the video ID is valid in the database
        permission_result = cursor.execute(
            "SELECT download_permission FROM videos WHERE public_video_id = ?", (public_video_id,)).fetchone()

        if permission_result is None:
            return error_page("Video not found.", 404)

        current_permission = permission_result[0]

        # Toggle download permission
        if current_permission == "disallowed":
            new_permission = "allowed"
            flash("Download permission granted successfully.", "success")
        else:
            new_permission = "disallowed"
            flash("Download permission revoked successfully.", "info")

        # Update the video record (e.g., set a download permission flag)
        cursor.execute("UPDATE videos SET download_permission = ? WHERE public_video_id = ?",
                       (new_permission, public_video_id))
        db.commit()  # Commit the changes to the database

        return redirect("/myvideos")  # Redirect to the My Videos page
    else:
        return error_page("No video ID provided.", 403)
