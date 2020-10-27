from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, EqualTo, Email, Length
from project.models import Team

class LoginForm(FlaskForm):
    username = StringField("Team name", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")

class RegistrationForm(FlaskForm):
    username = StringField("Team name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    password1 = PasswordField("Repeat Password", validators=[DataRequired(), EqualTo("password", message="Passwords must match")])
    submit = SubmitField("Register")

    def validate_username(self, username):
        user = Team.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError("Please use a different username.")

    def validate_email(self, email):
        user = Team.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("Please use a different email address.")

class EditProfileForm(FlaskForm):
    username = StringField("Team name", validators=[DataRequired()])
    about_us = TextAreaField("About us", validators=[Length(min=0, max=140)])
    submit = SubmitField("Edit")
