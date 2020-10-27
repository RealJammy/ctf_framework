from project import project, login, db
from project.forms import LoginForm, RegistrationForm, TeamRegistration
from project.models import User, Team
from flask import render_template, flash, redirect, url_for, request, session
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse

@project.route("/")
@project.route("/index")
@login_required
def index():
    user = {"username": "John"}
    posts = [{"author": {"username": "Susan"}, "body": "Testing 1 2 3"}]
    return render_template("index.html", title="Home", posts=posts)

@project.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or data", "error")
            return redirect(url_for("login"))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get("next")
        if not next_page or url_parse(next_page).netloc != "":
            next_page = url_for("index")
        return redirect(next_page)
    return render_template("login.html", title="Sign in", form=form)


@project.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))

@project.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Congratulations, you are now a registered user!")
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)

@project.route("/create_team", methods=["GET", "POST"])
@login_required
def create_team():
    form = TeamRegistration()
    if form.validate_on_submit():
        team = Team(name=form.team_name.data)
        team.set_password(form.password.data)
        db.session.add(team)
        db.session.commit()
        flash("Congratulations, you are now a registered team!")
    return render_template("create_team.html", title="Create team", form=form)

@project.route("/scoreboard")
def scoreboard():
    users = User.query.order_by(User.score).all()
    return render_template("scoreboard.html", title="Scoreboard", users=users)

@project.route("/challenges", methods=["GET", "POST"])
def challenges():
    form = ChallengeFlagForm()
    if request.method == "GET":
        categories = form.get_challenges()
        completed = UserChallenge.completed_challenges(user_id=current_user.id)
    return render_template("challenges.html", )
