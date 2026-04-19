import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from stego import embed_message, extract_message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['OUTPUT_FOLDER'] = 'static/outputs'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ======================
# MODELS
# ======================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(255))


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    mode = db.Column(db.String(50))
    start_bit = db.Column(db.Integer)
    interval_l = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='posts')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ======================
# ROUTES
# ======================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User(
            username=request.form['username'],
            email=request.form['email'],
            password_hash=generate_password_hash(request.form['password'])
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    user = User.query.filter_by(username=request.form.get('username')).first()
    if user and request.method == 'POST':
        if check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ======================
# PROFILE 
# ======================
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_username = request.form['username']
        new_email = request.form['email']

        # Optional: prevent duplicates
        existing_user = User.query.filter(
            (User.username == new_username) | (User.email == new_email)
        ).first()

        if existing_user and existing_user.id != current_user.id:
            flash("Username or email already taken", "danger")
            return redirect(url_for('profile'))

        current_user.username = new_username
        current_user.email = new_email

        db.session.commit()
        flash("Profile updated successfully", "success")
        return redirect(url_for('profile'))

    return render_template('profile.html')
# ======================
# CREATE
# ======================
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':

        file = request.files['carrier_file']
        filename = secure_filename(file.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)

        with open(path, 'rb') as f:
            carrier_bytes = f.read()

        output = embed_message(
            carrier_bytes,
            request.form['secret_text'].encode(),
            "secret.txt",
            int(request.form['start_bit']),
            int(request.form['interval_l']),
            request.form['mode']
        )

        output_filename = "stego_" + filename
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)

        with open(output_path, 'wb') as f:
            f.write(output)

        db.session.add(Post(
            filename=output_filename,
            mode=request.form['mode'],
            start_bit=request.form['start_bit'],
            interval_l=request.form['interval_l'],
            user_id=current_user.id
        ))
        db.session.commit()

        return redirect(url_for('gallery'))

    return render_template('create_post.html')


# ======================
# GALLERY
# ======================
@app.route('/gallery')
def gallery():
    return render_template('gallery.html', posts=Post.query.all())


# ======================
# MY POSTS
# ======================
@app.route('/my-posts')
@login_required
def my_posts():
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('my_posts.html', posts=posts)


# ======================
# DELETE
# ======================
@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_post(id):
    post = Post.query.get(id)

    if post.user_id != current_user.id:
        flash("Unauthorized", "danger")
        return redirect(url_for('my_posts'))

    file_path = os.path.join(app.config['OUTPUT_FOLDER'], post.filename)
    if os.path.exists(file_path):
        os.remove(file_path)

    db.session.delete(post)
    db.session.commit()

    flash("Deleted successfully", "success")
    return redirect(url_for('my_posts'))


# ======================
# DOWNLOAD
# ======================
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['OUTPUT_FOLDER'], filename, as_attachment=True)


# ======================
# EXTRACT
# ======================
@app.route('/extract', methods=['GET', 'POST'])
@login_required
def extract_view():
    extracted_text = None

    if request.method == 'POST':
        file = request.files['stego_file']
        data = file.read()

        try:
            name, content = extract_message(
                data,
                int(request.form['start_bit']),
                int(request.form['interval_l']),
                request.form['mode']
            )
            extracted_text = content.decode()
        except:
            extracted_text = "Could not decode message"

    return render_template('extract.html', extracted_text=extracted_text)


# ======================
# RUN
# ======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)