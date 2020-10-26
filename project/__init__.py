from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config

project = Flask(__name__)
project.config.from_object(Config)
db = SQLAlchemy(project)
migrate = Migrate(project, db)

from project import routes, models
