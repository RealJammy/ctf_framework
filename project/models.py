from project import db, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_security import RoleMixin
from hashlib import md5
from datetime import datetime

association_table = db.Table("association",
    db.Column("team_id", db.Integer, db.ForeignKey("team.id")),
    db.Column("challenge_id", db.Integer, db.ForeignKey("challenge.id"))
)

roles_teams_table = db.Table("roles_teams",
    db.Column("team_id", db.Integer(), db.ForeignKey("team.id")),
    db.Column("roles_id", db.Integer(), db.ForeignKey("roles.id"))
)

class Team(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(128), index=True, unique=True)
    email = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    score = db.Column(db.Integer, default=0)
    about_us = db.Column(db.String(400), default="Nothing to see here")
    flags = db.relationship("Challenge", secondary=association_table)
    last_flag = db.Column(db.DateTime, default=datetime.utcnow())
    active = db.Column(db.Boolean(), default=1)
    roles = db.relationship("Roles", secondary=roles_teams_table, backref="team", lazy=True)

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
    title = db.Column(db.String(128))
    description = db.Column(db.Text)
    points = db.Column(db.Integer)
    flag = db.Column(db.String(64))
    category = db.Column(db.String(32))
    file_path = db.Column(db.String(256))

    def __repr__(self):
        return f"Challenge({self.title}, {self.category})"

class Roles(RoleMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

    def __repr__(self):
        return f"Roles({self.name})"
