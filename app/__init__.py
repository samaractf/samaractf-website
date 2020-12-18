import os
from flask import Flask
from config import DevelopmentConfig
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_mail import Mail
from flask_principal import (
    ActionNeed,
    AnonymousIdentity,
    Identity,
    identity_changed,
    identity_loaded,
    Permission,
    Principal,
    RoleNeed)


app = Flask(__name__)
app.config.from_object("config.DevelopmentConfig")
login = LoginManager(app)
login.login_view = 'login'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)




def inject_permissions():
    return dict(Permission=Permission)

from app import routes, models



