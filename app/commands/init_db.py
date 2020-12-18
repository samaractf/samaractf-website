from flask import current_app
from flask_script import Command
from app.models import Tag, User, Role
from app import db


class InitDbCommand(Command):
    """ Initialize the database."""

    def run(self):
        init_db()
        print('Database has been initialized.')


def init_db():
    """ Initialize the database."""
    db.drop_all()
    db.create_all()
    create_tables()


def create_tables():
    """ Create users """

    # Create all tables
    db.create_all()

    tag = Tag.query.first()
    if not tag:
        tag = Tag(name='news')
        db.session.add(tag)
    # Adding roles
    # admin_role = find_or_create_role('admin', u'Admin')
    role = Role.query.first()
    if not role:
        role = Role.insert_roles()
    # Add users
    user = find_or_create_user('GlKorol', 'admin@samaractf.ru', 'GlKorol') #switch the password after successfully login
    print('switch the password <GlKorol> after successfully login')


    # Save to DB

    db.session.commit()


def find_or_create_user(username, email, password):
    user = User.query.filter(User.email == email).first()
    if not user:
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
    return user
