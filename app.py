import os
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2 import IntegrityError, Error
from datetime import date

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

DATABASE_URL = os.getenv("DATABASE_URL")


def get_connection():
    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require"
    )


def initialize_database():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            phone VARCHAR(20) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL DEFAULT 'user'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id SERIAL PRIMARY KEY,
            event_name VARCHAR(150) NOT NULL,
            description TEXT NOT NULL,
            event_date DATE NOT NULL,
            event_time TIME NOT NULL,
            venue VARCHAR(200) NOT NULL,
            capacity INT NOT NULL DEFAULT 100,
            status VARCHAR(20) NOT NULL DEFAULT 'Available'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS registrations (
            registration_id SERIAL PRIMARY KEY,
            user_id INT NOT NULL,
            event_id INT NOT NULL,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(30) NOT NULL DEFAULT 'Registered',
            UNIQUE (user_id, event_id),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        INSERT INTO users
        (name, email, phone, password_hash, role)
        VALUES (%s, %s, %s, %s, 'admin')
        ON CONFLICT (email) DO NOTHING
    """, (
        "Administrator",
        "admin@event.com",
        "9999999999",
        generate_password_hash("admin123")
    ))

    conn.commit()
    cur.close()
    conn.close()


def user_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.", "warning")
            return redirect(url_for("login"))

        if session.get("role") != "user":
            flash("User access only.", "danger")
            return redirect(url_for("admin_dashboard"))

        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            flash("Admin login required.", "warning")
            return redirect(url_for("admin_login"))

        return fn(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT e.*,
        (SELECT COUNT(*) FROM registrations r
         WHERE r.event_id=e.event_id
         AND r.status='Registered') AS registered_count
        FROM events e
        WHERE e.status='Available'
        ORDER BY e.event_date
    """)

    events = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "index.html",
        events=events,
        today=date.today().isoformat()
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not name or not email or not phone or not password:
            flash("Please fill all fields.", "danger")
            return redirect(url_for("register"))

        conn = get_connection()
        cur = conn.cursor()

        try:
            cur.execute("""
                INSERT INTO users
                (name, email, phone, password_hash, role)
                VALUES (%s, %s, %s, %s, 'user')
            """, (
                name,
                email,
                phone,
                generate_password_hash(password)
            ))

            conn.commit()
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))

        except IntegrityError:
            flash("Email already registered.", "danger")

        finally:
            cur.close()
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT * FROM users
            WHERE email=%s AND LOWER(role)='user'
        """, (email,))

        user = cur.fetchone()
        cur.close()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["user_id"]
            session["name"] = user["name"]
            session["role"] = "user"

            flash("Login successful.", "success")
            return redirect(url_for("home"))

        flash("Invalid user email or password.", "danger")

    return render_template("login.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT * FROM users
            WHERE email=%s AND LOWER(role)='admin'
        """, (email,))

        admin = cur.fetchone()
        cur.close()
        conn.close()

        if admin and check_password_hash(admin["password_hash"], password):
            session.clear()
            session["user_id"] = admin["user_id"]
            session["name"] = admin["name"]
            session["role"] = "admin"

            flash("Admin login successful.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin email or password.", "danger")

    return render_template("admin_login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


@app.route("/event/<int:event_id>")
def event_details(event_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT e.*,
        (SELECT COUNT(*) FROM registrations r
         WHERE r.event_id=e.event_id
         AND r.status='Registered') AS registered_count
        FROM events e
        WHERE e.event_id=%s
    """, (event_id,))

    event = cur.fetchone()
    cur.close()
    conn.close()

    if not event:
        flash("Event not found.", "danger")
        return redirect(url_for("home"))

    return render_template("event_details.html", event=event)


@app.route("/event/register/<int:event_id>")
@user_required
def event_register_form(event_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT * FROM events
        WHERE event_id=%s AND status='Available'
    """, (event_id,))

    event = cur.fetchone()
    cur.close()
    conn.close()

    if not event:
        flash("Event not available.", "danger")
        return redirect(url_for("home"))

    return render_template("event_register.html", event=event)


@app.route("/event/register/submit/<int:event_id>", methods=["POST"])
@user_required
def register_event(event_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cur.execute("""
            SELECT * FROM events
            WHERE event_id=%s AND status='Available'
        """, (event_id,))

        event = cur.fetchone()

        if not event:
            flash("Event not available.", "danger")
            return redirect(url_for("home"))

        cur.execute("""
            SELECT * FROM registrations
            WHERE user_id=%s AND event_id=%s
            FOR UPDATE
        """, (session["user_id"], event_id))

        old_registration = cur.fetchone()

        if old_registration and old_registration["status"] == "Registered":
            flash("You have already registered for this event.", "warning")
            return redirect(url_for("my_registrations"))

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM registrations
            WHERE event_id=%s AND status='Registered'
        """, (event_id,))

        count = cur.fetchone()["total"]

        if count >= event["capacity"]:
            flash("Event capacity is full.", "danger")
            return redirect(url_for("event_details", event_id=event_id))

        if old_registration:
            cur.execute("""
                UPDATE registrations
                SET status='Registered'
                WHERE registration_id=%s
            """, (old_registration["registration_id"],))
        else:
            cur.execute("""
                INSERT INTO registrations (user_id, event_id)
                VALUES (%s, %s)
            """, (session["user_id"], event_id))

        conn.commit()
        flash("Event registration successful.", "success")

    except Error as e:
        conn.rollback()
        flash("Registration failed. Please try again.", "danger")

    finally:
        cur.close()
        conn.close()

    return redirect(url_for("my_registrations"))
    
@app.route("/my-registrations")
@user_required
def my_registrations():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT r.registration_id, r.registration_date, r.status,
               e.event_id, e.event_name, e.event_date,
               e.event_time, e.venue
        FROM registrations r
        JOIN events e ON r.event_id=e.event_id
        WHERE r.user_id=%s
        ORDER BY r.registration_date DESC
    """, (session["user_id"],))

    registrations = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "my_registrations.html",
        registrations=registrations
    )


@app.route("/cancel-registration/<int:registration_id>", methods=["POST"])
@user_required
def cancel_registration(registration_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE registrations
        SET status='Cancelled'
        WHERE registration_id=%s AND user_id=%s
    """, (registration_id, session["user_id"]))

    conn.commit()

    if cur.rowcount > 0:
        flash("Registration cancelled.", "success")
    else:
        flash("Registration not found.", "danger")

    cur.close()
    conn.close()

    return redirect(url_for("my_registrations"))


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT COUNT(*) AS total FROM events")
    total_events = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM users WHERE LOWER(role)='user'")
    total_users = cur.fetchone()["total"]

    cur.execute("""
        SELECT COUNT(*) AS total FROM registrations
        WHERE status='Registered'
    """)
    total_registrations = cur.fetchone()["total"]

    cur.execute("""
        SELECT e.*,
        (SELECT COUNT(*) FROM registrations r
         WHERE r.event_id=e.event_id
         AND r.status='Registered') AS registered_count
        FROM events e
        ORDER BY e.event_date DESC
    """)

    events = cur.fetchall()

    cur.close()
    conn.close()

    return render_template(
        "admin_dashboard.html",
        events=events,
        total_events=total_events,
        total_users=total_users,
        total_registrations=total_registrations
    )


@app.route("/admin/event/add", methods=["GET", "POST"])
@admin_required
def add_event():
    if request.method == "POST":
        event_name = request.form.get("event_name", "").strip()
        description = request.form.get("description", "").strip()
        event_date = request.form.get("event_date", "")
        event_time = request.form.get("event_time", "")
        venue = request.form.get("venue", "").strip()
        capacity = request.form.get("capacity", "100")

        if not all([event_name, description, event_date, event_time, venue]):
            flash("Please fill all fields.", "danger")
            return redirect(url_for("add_event"))

        try:
            capacity = int(capacity)
            if capacity < 1:
                raise ValueError

            conn = get_connection()
            cur = conn.cursor()

            cur.execute("""
                INSERT INTO events
                (event_name, description, event_date,
                 event_time, venue, capacity)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                event_name,
                description,
                event_date,
                event_time,
                venue,
                capacity
            ))

            conn.commit()
            cur.close()
            conn.close()

            flash("Event added successfully.", "success")
            return redirect(url_for("admin_dashboard"))

        except ValueError:
            flash("Please enter a valid capacity.", "danger")

    return render_template("event_form.html", event=None)


@app.route("/admin/event/edit/<int:event_id>", methods=["GET", "POST"])
@admin_required
def edit_event(event_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT * FROM events WHERE event_id=%s", (event_id,))
    event = cur.fetchone()

    if not event:
        cur.close()
        conn.close()
        flash("Event not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        event_name = request.form.get("event_name", "").strip()
        description = request.form.get("description", "").strip()
        event_date = request.form.get("event_date", "")
        event_time = request.form.get("event_time", "")
        venue = request.form.get("venue", "").strip()
        capacity = request.form.get("capacity", "100")

        try:
            capacity = int(capacity)

            if not all([event_name, description, event_date, event_time, venue]) or capacity < 1:
                raise ValueError

            cur.execute("""
                UPDATE events
                SET event_name=%s, description=%s,
                    event_date=%s, event_time=%s,
                    venue=%s, capacity=%s
                WHERE event_id=%s
            """, (
                event_name,
                description,
                event_date,
                event_time,
                venue,
                capacity,
                event_id
            ))

            conn.commit()
            cur.close()
            conn.close()

            flash("Event updated successfully.", "success")
            return redirect(url_for("admin_dashboard"))

        except ValueError:
            flash("Please enter valid event details.", "danger")

    cur.close()
    conn.close()

    return render_template("event_form.html", event=event)


@app.route("/admin/event/delete/<int:event_id>", methods=["POST"])
@admin_required
def delete_event(event_id):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("DELETE FROM events WHERE event_id=%s", (event_id,))
    conn.commit()

    cur.close()
    conn.close()

    flash("Event deleted successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/registrations")
@admin_required
def admin_registrations():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("""
        SELECT r.registration_id, r.registration_date, r.status,
               u.name, u.email, u.phone,
               e.event_name, e.event_date
        FROM registrations r
        JOIN users u ON r.user_id=u.user_id
        JOIN events e ON r.event_id=e.event_id
        ORDER BY r.registration_date DESC
    """)

    registrations = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        "admin_registrations.html",
        registrations=registrations
    )


initialize_database()
if __name__ == "__main__":
    app.run(debug=True)
