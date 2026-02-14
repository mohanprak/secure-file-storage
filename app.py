from flask import Flask, render_template, request, redirect, session, send_file
from flask_mysqldb import MySQL
import bcrypt
import os
from encryption import encrypt_file, decrypt_file
import db_config

app = Flask(__name__)
app.secret_key = "super_secret_key"

# MySQL Configuration
app.config["MYSQL_HOST"] = db_config.MYSQL_HOST
app.config["MYSQL_USER"] = db_config.MYSQL_USER
app.config["MYSQL_PASSWORD"] = db_config.MYSQL_PASSWORD
app.config["MYSQL_DB"] = db_config.MYSQL_DB

mysql = MySQL(app)

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted_files"
DECRYPTED_FOLDER = "decrypted_temp"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Home Page
@app.route("/")
def index():
    return render_template("index.html")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name,email,password_hash) VALUES(%s,%s,%s)",
                    (name, email, hashed_password))
        mysql.connection.commit()
        cur.close()

        return redirect("/login")

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()

        if user:
            user_id = user[0]
            user_name = user[1]
            user_email = user[2]
            stored_hash = user[3]
            role = user[4]

            if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8') if isinstance(stored_hash, str) else stored_hash):
                session["user_id"] = user_id
                session["name"] = user_name
                session["role"] = role
                return redirect("/dashboard")

        return "Invalid Login!"

    return render_template("login.html")

# Dashboard
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM files WHERE user_id=%s", (user_id,))
    files = cur.fetchall()
    cur.close()

    return render_template("dashboard.html", files=files, name=session["name"])

# Upload File
@app.route("/upload", methods=["POST"])
def upload():
    if "user_id" not in session:
        return redirect("/login")

    file = request.files["file"]
    if file:
        filename = file.filename
        upload_path = os.path.join(UPLOAD_FOLDER, filename)
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename + ".enc")

        file.save(upload_path)

        # Encrypt File
        encrypt_file(upload_path, encrypted_path)

        # Delete original file
        os.remove(upload_path)

        # Save in database
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO files(user_id,file_name,encrypted_file_path) VALUES(%s,%s,%s)",
                    (session["user_id"], filename, encrypted_path))
        mysql.connection.commit()
        cur.close()

        return redirect("/dashboard")

# Download File
@app.route("/download/<int:file_id>")
def download(file_id):
    if "user_id" not in session:
        return redirect("/login")

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM files WHERE id=%s AND user_id=%s", (file_id, session["user_id"]))
    file_data = cur.fetchone()
    cur.close()

    if not file_data:
        return "Unauthorized Access!"

    encrypted_path = file_data[3]
    original_name = file_data[2]
    decrypted_path = os.path.join(DECRYPTED_FOLDER, original_name)

    decrypt_file(encrypted_path, decrypted_path)

    return send_file(decrypted_path, as_attachment=True)

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)

    from flask import Flask
from flask_mysqldb import MySQL
import db_config

app = Flask(__name__)

# MySQL Configuration
app.config["MYSQL_HOST"] = db_config.MYSQL_HOST
app.config["MYSQL_USER"] = db_config.MYSQL_USER
app.config["mohan"] = db_config.MYSQL_PASSWORD
app.config["MYSQL_DB"] = db_config.MYSQL_DB

mysql = MySQL(app)

@app.route("/")
def home():
    return "MySQL Connected Successfully!"

if __name__ == "__main__":
    app.run(debug=True)

    from flask import Flask, render_template, request, redirect, session
from flask_mysqldb import MySQL

app = Flask(__name__)
app.secret_key = "secretkey123"

# MySQL Connection Config
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["password"] = "your_mysql_password"
app.config["MYSQL_DB"] = "secure_storage"

mysql = MySQL(app)

# Home page (redirect to register)
@app.route("/")
def home():
    return redirect("/register")


# Register Page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO users(name,email,password) VALUES(%s,%s,%s)",
                    (name, email, password))
        mysql.connection.commit()
        cur.close()

        return redirect("/login")

    return render_template("register.html")


# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE email=%s AND password=%s", (email, password))
        user = cur.fetchone()
        cur.close()

        if user:
            session["user_id"] = user[0]
            session["name"] = user[1]
            return redirect("/dashboard")
        else:
            return "Invalid Login Details!"

    return render_template("login.html")


# Dashboard Page
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    return render_template("dashboard.html", name=session["name"])


# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)


@app.route("/")
def index():

    return render_template("index.html")

if __name__ == "__main__":
    app.run()