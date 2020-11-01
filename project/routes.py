from project import project, login_manager, db, admin
from project.forms import LoginForm, RegistrationForm, EditProfileForm, SubmitFlagForm
from project.models import Team, Challenge
from project.create_db import add_challenges
from flask import render_template, flash, redirect, url_for, request, session
from flask_login import current_user, login_user, logout_user, login_required, AnonymousUserMixin
from flask_admin.contrib.sqla import ModelView
from werkzeug.urls import url_parse
from hashlib import sha256
from datetime import datetime
import os

class TeamModelView(ModelView):
    def is_accessible(self):
        if current_user.is_anonymous:
            return False
        return current_user.username == Team.query.filter_by(username=os.getenv("ADMIN_NAME")).first().username

    def _handle_view(self, name):
        if not self.is_accessible():
                return redirect(url_for("login"))

admin.add_view(TeamModelView(Team, db.session))
admin.add_view(TeamModelView(Challenge, db.session))

@project.before_first_request
def create_user():
    if Team.query.filter_by(username=os.getenv("ADMIN_NAME")).first():
        return None
    else:
        admin = Team(username=os.getenv("ADMIN_NAME"), email=os.getenv("ADMIN_EMAIL"))
        admin.set_password(os.getenv("ADMIN_PWD"))
        db.session.add(admin)
        db.session.commit()

@login_manager.user_loader
def load_user(id):
    return Team.query.get(int(id))

class Anonymous(AnonymousUserMixin):
    def __init__(self):
        self.username = "Guest"

login_manager.anonymous_user = Anonymous

@project.route("/")
@project.route("/index")
@login_required
def index():
    return render_template("index.html", title="Home")

@project.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        team = Team.query.filter_by(username=form.username.data).first()
        if team is None or not team.check_password(form.password.data):
            flash("Invalid username or data", "danger")
            return redirect(url_for("login"))
        login_user(team, remember=form.remember_me.data)
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
        team = Team(username=form.username.data, email=form.email.data)
        team.set_password(form.password.data)
        db.session.add(team)
        db.session.commit()
        flash("Congratulations, you are now a registered team!", "success")
        return redirect(url_for("login"))
    return render_template("register.html", title="Register", form=form)

@project.route("/profile/<username>")
def profile(username):
    team = Team.query.filter_by(username=username).first_or_404()
    return render_template("profile.html", title="Your Profile", team=team)

@project.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_us = form.about_us.data
        current_user.password = current_user.set_password(form.password.data)
        db.session.commit()
        flash("Your changes have been saved.", "success")
        return redirect(url_for("edit_profile"))
    elif request.method == "GET":
        form.username.data = current_user.username
        form.about_us.data = current_user.about_us
    return render_template("edit_profile.html", title="Edit Profile", form=form)

@project.route("/scoreboard")
def scoreboard():
    users = Team.query.order_by(Team.score.desc()).all()
    return render_template("scoreboard.html", title="Scoreboard", users=users)

@project.route("/challenges", methods=["GET", "POST"])
@login_required
def challenges():
    all_challenges = Challenge.query.all()
    form = SubmitFlagForm()
    if form.validate_on_submit():
        challenge_id = request.form["submit_btn"][6:]
        challenge = Challenge.query.filter_by(id=challenge_id).first()
        flag = form.flag.data
        team = Team.query.filter_by(username=current_user.username).first()
        if challenge in team.flags:
            flash("You've already entered that flag.", "warning")
            return redirect(url_for("challenges"))
        if flag == challenge.flag:
            team.flags.append(challenge)
            team.score += challenge.points
            team.last_flag = datetime.utcnow()
            db.session.add(team)
            db.session.commit()
            flash("Well done, that's correct", "success")
            return redirect(url_for("challenges"))
        else:
            flash("Invalid flag", "danger")
            return redirect(url_for("challenges"))
    return render_template("challenge.html", title="Challenges", challenges=all_challenges, form=form)
