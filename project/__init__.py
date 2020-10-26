from flask import Flask

project = Flask(__name__)

from project import routes
