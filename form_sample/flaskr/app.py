from flask import Flask

from flaskr.database import init_db
import flaskr.models

def create_app():
    app = Flask(__name__)
    app.config.from_object('flaskr.config.Config')

    init_db(app)
    return app

app = create_app()