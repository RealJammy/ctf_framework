from project import project
from flask import render_template

@project.route("/")
@project.route("/index")
def index():
    user = {"username": "John"}
    posts = [{"author": {"username": "Susan"}, "body": "Testing 1 2 3"}]
    return render_template("index.html", title="Home", user=user, posts=posts)
