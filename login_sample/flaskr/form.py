from wtforms.form import Form
from wtforms.fields import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import ValidationError
from flaskr.models import User

class LoginForm(Form):
    email = StringField('email: ', validators=[DataRequired(), Email()])
    password = PasswordField('password: ', validators=[DataRequired(), ])
    submit = SubmitField('Login')

class RegisterForm(Form):
    email = StringField('email: ', validators=[DataRequired(), Email()])
    username = StringField('username: ', validators=[DataRequired()])
    password = PasswordField('password: ', validators=[DataRequired(), EqualTo('password_confirm', message='not match password')])
    password_confirm = PasswordField('password confirm: ', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.select_by_email(field.data):
            raise ValidationError('Email address already used.')