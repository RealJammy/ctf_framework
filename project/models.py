from project import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from hashlib import md5
from datetime import datetime

association_table = db.Table("association",
    db.Column("team_id", db.Integer, db.ForeignKey("team.id")),
    db.Column("challenge_id", db.Integer, db.ForeignKey("challenge.id"))
)

@login.user_loader
def load_user(id):
    return Team.query.get(int(id))

class Team(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), index=True, unique=True)
    email = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    score = db.Column(db.Integer, default=0)
    about_us = db.Column(db.String(400), default="Nothing to see here")
    flags = db.relationship("Challenge", secondary=association_table)
    last_flag = db.Column(db.DateTime, default=datetime.utcnow())

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f"https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}"

    def __repr__(self):
        return f"Team({self.username}, {self.score})"

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), unique=True)
    description = db.Column(db.Text)
    points = db.Column(db.Integer)
    flag_hash = db.Column(db.String(64))
    category = db.Column(db.String(32))
