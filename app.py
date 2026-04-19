import os
import secrets

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
    session,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from sqlalchemy import inspect, text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from stego import embed_message, extract_message

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-with-env")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["OUTPUT_FOLDER"] = "static/outputs"

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["OUTPUT_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# ======================
# MODELS
# ======================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    secret_filename = db.Column(db.String(200))
    mode = db.Column(db.String(50), nullable=False)
    start_bit = db.Column(db.Integer, nullable=False)
    interval_l = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    user = db.relationship("User", backref="posts")


def ensure_schema():
    """Create tables and add new columns on existing SQLite DBs."""
    db.create_all()
    try:
        inspector = inspect(db.engine)
        table_names = inspector.get_table_names()
        if "post" in table_names:
            cols = [c["name"] for c in inspector.get_columns("post")]
            if "secret_filename" not in cols:
                db.session.execute(
                    text("ALTER TABLE post ADD COLUMN secret_filename VARCHAR(200)")
                )
                db.session.commit()
    except Exception:
        db.session.rollback()


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ======================
# ROUTES
# ======================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")

        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing:
            flash("Username or email already registered.", "danger")
            return render_template("register.html")

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    recent_posts = (
        Post.query.filter_by(user_id=current_user.id)
        .order_by(Post.id.desc())
        .limit(5)
        .all()
    )
    return render_template("dashboard.html", recent_posts=recent_posts)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("index"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        new_username = request.form.get("username", "").strip()
        new_email = request.form.get("email", "").strip()

        if not new_username or not new_email:
            flash("Username and email cannot be empty.", "danger")
            return redirect(url_for("profile"))

        existing_user = User.query.filter(
            (User.username == new_username) | (User.email == new_email)
        ).first()

        if existing_user and existing_user.id != current_user.id:
            flash("Username or email already taken.", "danger")
            return redirect(url_for("profile"))

        current_user.username = new_username
        current_user.email = new_email
        db.session.commit()

        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile"))

    return render_template("profile.html")


@app.route("/create", methods=["GET", "POST"])
@login_required
def create_post():
    if request.method == "POST":
        carrier = request.files.get("carrier_file")
        secret_file = request.files.get("secret_message")
        secret_text = request.form.get("secret_text", "").strip()
        mode = request.form.get("mode", "fixed")

        try:
            start_bit = int(request.form.get("start_bit", 1024))
            interval_l = int(request.form.get("interval_l", 8))
        except ValueError:
            flash("Starting bit and interval must be valid numbers.", "danger")
            return redirect(url_for("create_post"))

        if not carrier or not carrier.filename:
            flash("Please upload a carrier file.", "warning")
            return redirect(url_for("create_post"))

        carrier_name = secure_filename(carrier.filename)
        if not carrier_name:
            flash("Invalid carrier filename.", "danger")
            return redirect(url_for("create_post"))

        has_secret_file = bool(secret_file and secret_file.filename)
        if has_secret_file:
            secret_name = secure_filename(secret_file.filename)
            secret_bytes = secret_file.read()
        elif secret_text:
            secret_name = "message.txt"
            secret_bytes = secret_text.encode("utf-8")
        else:
            flash("Enter a secret message or upload a secret file.", "warning")
            return redirect(url_for("create_post"))

        carrier_path = os.path.join(app.config["UPLOAD_FOLDER"], carrier_name)
        carrier.save(carrier_path)

        try:
            with open(carrier_path, "rb") as f:
                carrier_bytes = f.read()

            output = embed_message(
                carrier_bytes,
                secret_bytes,
                secret_name,
                start_bit,
                interval_l,
                mode,
            )
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("create_post"))
        except Exception:
            flash("An unexpected error occurred during embedding.", "danger")
            return redirect(url_for("create_post"))

        output_filename = "stego_" + carrier_name
        output_path = os.path.join(app.config["OUTPUT_FOLDER"], output_filename)

        with open(output_path, "wb") as f:
            f.write(output)

        new_post = Post(
            filename=output_filename,
            secret_filename=secret_name,
            mode=mode,
            start_bit=start_bit,
            interval_l=interval_l,
            user_id=current_user.id,
        )
        db.session.add(new_post)
        db.session.commit()

        flash("Stego file created successfully.", "success")
        return redirect(url_for("gallery"))

    return render_template("create_post.html")


@app.route("/gallery")
def gallery():
    posts = Post.query.order_by(Post.id.desc()).all()
    return render_template("gallery.html", posts=posts)


@app.route("/my-posts")
@login_required
def my_posts():
    posts = (
        Post.query.filter_by(user_id=current_user.id)
        .order_by(Post.id.desc())
        .all()
    )
    return render_template("my_posts.html", posts=posts)


@app.route("/delete/<int:id>", methods=["POST"])
@login_required
def delete_post(id):
    post = db.session.get(Post, id)

    if post is None or post.user_id != current_user.id:
        flash("Unauthorized action.", "danger")
        return redirect(url_for("my_posts"))

    file_path = os.path.join(app.config["OUTPUT_FOLDER"], post.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(post)
    db.session.commit()

    flash("Post deleted successfully.", "success")
    return redirect(url_for("my_posts"))


@app.route("/download/<filename>")
def download_file(filename):
    return send_from_directory(
        app.config["OUTPUT_FOLDER"],
        filename,
        as_attachment=True,
    )


@app.route("/extract", methods=["GET", "POST"])
@login_required
def extract_view():
    extracted_text = None
    extracted_filename = None
    extracted_hex_preview = None
    extracted_size = None
    extract_is_text = False

    if request.method == "POST":
        file = request.files.get("stego_file")
        if not file or not file.filename:
            flash("Please upload a stego file.", "warning")
        else:
            data = file.read()
            try:
                name, content = extract_message(
                    data,
                    int(request.form.get("start_bit", 1024)),
                    int(request.form.get("interval_l", 8)),
                    request.form.get("mode", "fixed"),
                )

                extracted_filename = name
                extracted_size = len(content)

                prev = session.get("extract_download")
                if prev:
                    prev_path = os.path.join(app.config["OUTPUT_FOLDER"], prev)
                    if os.path.isfile(prev_path):
                        os.remove(prev_path)

                dl_base = "extract_" + secrets.token_hex(16)
                dl_path = os.path.join(app.config["OUTPUT_FOLDER"], dl_base)
                with open(dl_path, "wb") as f:
                    f.write(content)

                session["extract_download"] = dl_base
                session["extract_original_name"] = secure_filename(name) or "recovered.bin"

                try:
                    extracted_text = content.decode("utf-8")
                    extract_is_text = True
                except UnicodeDecodeError:
                    extracted_text = None
                    extract_is_text = False
                    extracted_hex_preview = content[:128].hex()

                flash("Message extracted successfully.", "success")

            except ValueError as e:
                session.pop("extract_download", None)
                session.pop("extract_original_name", None)
                flash(str(e), "danger")
            except Exception:
                session.pop("extract_download", None)
                session.pop("extract_original_name", None)
                flash("An unexpected extraction error occurred.", "danger")

    show_download = bool(session.get("extract_download"))

    return render_template(
        "extract.html",
        extracted_text=extracted_text,
        extracted_filename=extracted_filename,
        extracted_hex_preview=extracted_hex_preview,
        extracted_size=extracted_size,
        extract_is_text=extract_is_text,
        show_download=show_download,
    )


@app.route("/extract/download")
@login_required
def download_extracted():
    basename = session.pop("extract_download", None)
    orig_name = session.pop("extract_original_name", "payload.bin")

    if not basename:
        flash("Nothing to download.", "warning")
        return redirect(url_for("extract_view"))

    path = os.path.join(app.config["OUTPUT_FOLDER"], basename)
    if not os.path.isfile(path):
        flash("Extracted file not found.", "danger")
        return redirect(url_for("extract_view"))

    return send_from_directory(
        app.config["OUTPUT_FOLDER"],
        basename,
        as_attachment=True,
        download_name=orig_name,
    )


with app.app_context():
    ensure_schema()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port, debug=True)