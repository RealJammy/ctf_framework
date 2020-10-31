from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_bs4 import Bootstrap
from flask_moment import Moment
from flask_admin import Admin
from config import Config

project = Flask(__name__)
project.config.from_object(Config)
db = SQLAlchemy(project)
migrate = Migrate(project, db)
login_manager = LoginManager(project)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
bootstrap = Bootstrap(project)
moment = Moment(project)
project.config["FLASK_ADMIN_SWATCH"] = "cosmo"
admin = Admin(project, template_mode="bootstrap3")

from project import routes, models
