import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager

from flaskr.utils.template_filters import replace_newline

login_manager = LoginManager()
login_manager.login_view = 'app.view'
login_manager.login_messeage = 'you have to login.'

base_dir = os.path.abspath(os.path.dirname(__name__))
flask_dir = os.path.abspath(os.path.dirname(__file__))
db = SQLAlchemy()
migrate = Migrate()

def create_app():
    app = Flask(__name__)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'mylogin'
    app.config['FLASK_DIR'] = flask_dir
    app.config['STATIC'] = os.path.join(flask_dir, 'static')
    app.config['IMG_DIR'] = 'user_image/'

    app.config['SQLALCHEMY_DATABASE_URI'] = \
        'sqlite:///' + os.path.join(base_dir, 'data.sqlite')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    from flaskr.views import bp
    app.register_blueprint(bp)
    app.add_template_filter(replace_newline)
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    return app