#!/bin/bash

python3 -m venv venv_flask
source venv_flask/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cd SNS_sample
export FLASK_APP="run.py"
flask db init
flask db migrate -m 'first migrate'
flask db upgrade
