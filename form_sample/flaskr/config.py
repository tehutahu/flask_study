import os

base_dir = os.path.dirname(__file__)

class DevelopmentConfig:
    # flask
    DEBUG = True
    SECRET_KEY = 'key'

    # SQLAlchemy
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(base_dir, 'data.sqlite')
    SQLALCHEMY_TRACK_MODIFICATIONS = True


Config = DevelopmentConfig