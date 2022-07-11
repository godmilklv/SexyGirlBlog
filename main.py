from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from forms import CreatePostForm, RegisterUser, LoginUser, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os


# App initializations
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "12345678")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app, size=200, rating='r', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)


# Class and Function definitions
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey("users.id"))
    author_user = relationship("User", back_populates="posts")
    post_comments = relationship("Comment", back_populates="comment_post")


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author_user")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    post_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    user_id = db.Column(db.Integer, ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    comment_post = relationship("BlogPost", back_populates="post_comments")


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def check_if_user_is_admin():
    if current_user.is_authenticated:
        if current_user.id == 1:
            return True
        else:
            return False
    else:
        return False


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# App Routes
@app.route('/', methods=["GET"])
def get_all_posts():
    admin = check_if_user_is_admin()
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, admin=admin)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterUser()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.data["email"]).first():
            flash("This email has already been registered, please login instead.")
            return redirect(url_for("login"))
        user_dict = {item: form.data[item] for item in form.data}
        del user_dict["submit"], user_dict["csrf_token"]
        user_dict["password"] = generate_password_hash(password=user_dict["password"],
                                                       method='pbkdf2:sha256',
                                                       salt_length=8)
        db.session.add(User(**user_dict))
        db.session.commit()
        new_user = User.query.filter_by(email=user_dict["email"]).first()
        del user_dict
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginUser()
    if form.validate_on_submit():
        user_to_login = User.query.filter_by(email=form.data["email"]).first()
        if user_to_login:
            if check_password_hash(user_to_login.password, form.data["password"]):
                login_user(user_to_login)
                return redirect(url_for("get_all_posts"))
            flash("The password you provided does not match our records.")
        else:
            flash("That email has not been registered yet.")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    admin = check_if_user_is_admin()
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            comment_dict = {
                "text": form.data["body"],
                "post_id": requested_post.id,
                "user_id": current_user.id,
            }
            db.session.add(Comment(**comment_dict))
            db.session.commit()
        else:
            flash("You need to be logged in to post a comment.")
            return redirect(url_for('login'))
    comments = Comment.query.filter_by(post_id=requested_post.id).all()
    return render_template("post.html", post=requested_post, admin=admin, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            author_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body)
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/delete-comment/<int:comment_id>')
def delete_comment(comment_id):
    post_id = request.args.get("post_id")
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
