from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from config import Config

project = Flask(__name__)
project.config.from_object(Config)
db = SQLAlchemy(project)
migrate = Migrate(project, db)
login = LoginManager(project)
login.login_view = "login"

from project import routes, models
