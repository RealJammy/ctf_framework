from project import project
from project.forms import LoginForm
from flask import render_template, flash, redirect

@project.route("/")
@project.route("/index")
def index():
    user = {"username": "John"}
    posts = [{"author": {"username": "Susan"}, "body": "Testing 1 2 3"}]
    return render_template("index.html", title="Home", user=user, posts=posts)

@project.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.vaildate_on_submit():
        flash(f"Login requested or user {form.username.data}, remember_me={form.remember_me.data}")
        return redirect(url_for("index"))
    return render_template("login.html", title="Sign in", form=form)
