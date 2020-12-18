
import os
basedir = os.path.abspath(os.path.dirname(__file__))
print(basedir)
class Config(object):
    DEBUG = False
    TESTING = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
                              'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True
    SECRET_KEY = 'Try-HackMe-:)'
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 25)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS') is not None
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ADMINS = ['admin@samaractf.ru']
    # set optional bootswatch theme
    FLASK_ADMIN_SWATCH = 'superhero'
    FLASKY_ADMIN = "admin@samaractf.ru"
    UPLOAD_FILE_FOLDER = basedir+'/app/uploads'
    UPLOAD_FILE_RELATIVE = '/uploads'
    UPLOAD_PHOTOS_FOLDER = basedir +'/app/uploads'
    UPLOAD_PHOTOS_RELATIVE = '/uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'zip', 'rar', 'png', 'jpg', 'jpeg', 'gif'}
    FLASKY_POSTS_PER_PAGE = 5

class TestingConfig(Config):
    TESTING = True
