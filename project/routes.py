from project import project
from project.forms import LoginForm
from flask import render_template

@project.route("/")
@project.route("/index")
def index():
    user = {"username": "John"}
    posts = [{"author": {"username": "Susan"}, "body": "Testing 1 2 3"}]
    return render_template("index.html", title="Home", user=user, posts=posts)

@project.route("/login")
def login():
    form = LoginForm()
    return render_template("login.html", title="Sign in", form=form)
