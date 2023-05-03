from flask import Flask, redirect, url_for, flash
from flask import render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, login_user, UserMixin, logout_user

from forms import LoginForm, SignUpForm
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime


import os
SECRET_KEY = os.urandom(32)


app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = "login"


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(75), unique=True)
    password = db.Column(db.String(75))

    def __repr__(self):
        return f"<users: {self.id}>"

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Profiles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(75), unique=True)
    name = db.Column(db.String(75))
    surname = db.Column(db.String(75))
    old = db.Column(db.Integer)
    city = db.Column(db.String(50))
    date_joined = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    def __repr__(self):
        return f"<profiles: {self.id}>"


@login.user_loader
def load_user(pk):
    return Users.query.get(int(pk))


@app.route("/")
def main_page():
    return render_template("main.html", user=current_user)


@app.route("/user/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))

    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('main_page'))
        else:
            flash('Invalid username or password')
            return redirect(url_for('login'))
    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("main_page"))


@app.route("/user/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main_page'))

    form = SignUpForm()
    if request.method == "POST":
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            if Users.query.get(username):
                return "User with such name already existed"

            user = Users()
            user.username = username
            user.set_password(password)
            db.session.add(user)
            db.session.commit()

            profile = Profiles(username=username, user_id=user.id)
            db.session.add(profile)
            db.session.commit()

            login_user(user)
            return redirect(url_for('main_page'))

    return render_template("register.html", form=form)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=True)
