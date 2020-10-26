from flask import Flask
from config import Config

project = Flask(__name__)
project.config.from_object(Config)

from project import routes
