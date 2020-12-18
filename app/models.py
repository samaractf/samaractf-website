from app import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, AnonymousUserMixin
import jwt
from app import login
from app import app
from time import time
from wtforms import widgets, TextAreaField
from flask_admin.contrib.sqla import ModelView
#import flask_principal
import datetime, json


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            print('role is None')
            print(app.config['FLASKY_ADMIN'])
            if self.email == app.config['FLASKY_ADMIN']:
                print("email == app.config['FLASKY_ADMIN']")
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()


    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(90), index=True, unique=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(256))
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    money = db.Column(db.Integer, default=0)
    posts = db.relationship('Page', backref='author', lazy='dynamic')
    tasks = db.relationship('Task', secondary="users_tasks")
    orders = db.relationship('Order', secondary="users_orders")


    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @login.user_loader
    def load_user(id):
        return User.query.get(int(id))

    def load_current_user(self):
        return User.query.filter(User.id == self.id).all()

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

    def can(self, permissions):
        return self.role is not None and self.role.has_permission(permissions)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def buy(self, cost):
        """
        buy order

        """
        if self.money >= cost >= 0:
            self.money -= cost
            return True
        else:
            return False
    def get_money(self, money):
        if money >= 0:
            self.money += money
            db.session.add(self)
            db.session.commit()
            return True
        else:
            return False

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': [Permission.FOLLOW],
            'SamaraUser': [Permission.FOLLOW, Permission.SAMARA],
            'Moderator': [Permission.FOLLOW, Permission.SAMARA,
                          Permission.WRITE, Permission.MODERATE],
            'Administrator': [Permission.FOLLOW, Permission.SAMARA,
                              Permission.WRITE, Permission.MODERATE,
                              Permission.ADMIN],
        }
        default_role = 'User'
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

    def has_permission(self, permissions):
        return self.permissions & permissions == permissions

    def reset_permissions(self):
        self.permissions = 0

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def __repr__(self):
        return '<Role %r>' % self.name
class Permission:
    FOLLOW = 1
    SAMARA = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16

#posts_tags = db.Table('posts_tags',
 #                     db.Column('tag_id', db.Integer, db.ForeignKey('tags.id')),
 #                     db.Column('posts_id', db.Integer, db.ForeignKey('posts.id')))
#https://overcoder.net/q/1250442/sqlalchemy-%D0%B2%D1%81%D1%82%D0%B0%D0%B2%D0%BA%D0%B0-%D0%B4%D0%B0%D0%BD%D0%BD%D1%8B%D1%85-%D0%B2-%D1%81%D0%B2%D1%8F%D0%B7%D0%B8-%D0%BC%D0%BD%D0%BE%D0%B3%D0%B8%D0%B5-%D0%BA%D0%BE-%D0%BC%D0%BD%D0%BE%D0%B3%D0%B8%D0%BC-%D1%81-%D1%82%D0%B0%D0%B1%D0%BB%D0%B8%D1%86%D0%B5%D0%B9-%D0%B0%D1%81%D1%81%D0%BE%D1%86%D0%B8%D0%B0%D1%86%D0%B8%D0%B8
#https://www.michaelcho.me/article/many-to-many-relationships-in-sqlalchemy-models-flask
#https://pythonru.com/uroki/15-osnovy-orm-sqlalchemy
class PostsTags(db.Model):
    __tablename__ = 'posts_tags2'

    id = db.Column("id",db.Integer, primary_key=True)

    tags_id = db.Column('tags_id',db.Integer, db.ForeignKey('tags.id'), nullable=False)
    posts_id = db.Column('posts_id',db.Integer, db.ForeignKey('posts.id'), nullable=False)

    tags = db.relationship('Tag', backref=db.backref("posts_tags2", cascade="all, delete-orphan"))
    posts = db.relationship('Page', backref=db.backref("posts_tags2", cascade="all, delete-orphan"))


"""PostsTags = db.Table('posts_tags2',
    db.Column('post_id', db.Integer, db.ForeignKey('posts.id')),
    db.Column('tag_id', db.Integer, db.ForeignKey('tags.id'))
)
"""

class Page(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    imagename = db.Column(db.String(512))
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default = datetime.datetime.now)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    tags = db.relationship('Tag', secondary="posts_tags2",)
    is_visible = db.Column(db.Boolean, unique=False, default=True)
    def __init__(self, tags, title, imagename, content,author_id, is_visible):
        self.tags.extend(tags)
        self.title = title
        self.imagename = imagename
        self.body = content
        self.author_id = author_id
        self.is_visible = is_visible
    def __unicode__(self):
        return self.title

#https://www.youtube.com/watch?v=OvhoYbjtiKc
#https://www.youtube.com/watch?v=poz824J33yg
#https://stonedastronaut.github.io/postroenie-sviazei-v-sqlalchemy.html
#Many-to-Many Inline Models flask
#https://stackoverflow.com/questions/52855750/flask-admin-how-to-do-inline-editing-for-manytomany-relations

class Tag(db.Model):
    __tablename__ = 'tags'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255)) #TODO ADD nullable=False
    posts = db.relationship("Page", secondary="posts_tags2")#, backref=db.backref('posts_tags', lazy='dynamic'))

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return str((self.id,self.name))


def tags_query():
    return Tag.query.order_by('name').paginate().items

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    short_about = db.Column(db.String(128), nullable=False)
    about = db.Column(db.String(2048), nullable=False)
    hint = db.Column(db.String(2048))
    category = db.Column(db.String(64), nullable=False)
    price = db.Column(db.Integer, default=0)
    flag = db.Column(db.String(256), default='SamaraCTF{TODO}')
    users = db.relationship("User", secondary="users_tasks")

class Order(db.Model):
    __tablename__ = "order"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(512), nullable=True)
    imagename = db.Column(db.String(1024))
    cost = db.Column(db.Integer, default=9999)
    secret = db.Column(db.String(5096))
    count = db.Column(db.Integer, default=0)
    users = db.relationship("User", secondary="users_orders")
#    def get_buyers:


class UsersOrder(db.Model):
    __tablename__ = 'users_orders'

    id = db.Column("id",db.Integer, primary_key=True)

    user_id = db.Column('user_id',db.Integer, db.ForeignKey('users.id'), nullable=False)
    order_id = db.Column('order_id',db.Integer, db.ForeignKey('order.id'), nullable=False)
    date = db.Column('data',db.DateTime,default=datetime.datetime.utcnow)
    users = db.relationship('User', backref=db.backref("users_orders", cascade="all, delete-orphan"))
    orders = db.relationship('Order', backref=db.backref("users_orders", cascade="all, delete-orphan"))


class UsersTasks(db.Model):
    __tablename__ = 'users_tasks'

    id = db.Column("id",db.Integer, primary_key=True)

    user_id = db.Column('user_id',db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_id = db.Column('task_id',db.Integer, db.ForeignKey('tasks.id'), nullable=False)
    data = db.Column('data', db.DateTime, default=datetime.datetime.utcnow)
    users = db.relationship('User', backref=db.backref("users_tasks", cascade="all, delete-orphan"))
    tasks = db.relationship('Task', backref=db.backref("users_tasks", cascade="all, delete-orphan"))


"""
#https://pythonhosted.org/Flask-Principal/
#https://github.com/mickey06/Flask-principal-example/blob/master/FPrincipals.py
class MyModelView(ModelView):

    def is_accessible(self):
        return current_user.is_authenticated
"""
