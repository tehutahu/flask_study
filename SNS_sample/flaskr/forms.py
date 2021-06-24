from wtforms.form import Form
from wtforms.fields import (
    StringField, PasswordField, SubmitField, HiddenField, FileField)
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms import ValidationError
from flask_login import current_user
from flask import flash

from flaskr.models import User

class LoginForm(Form):
    email = StringField('email: ', validators=[DataRequired(), Email()])
    password = PasswordField('password: ', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(Form):
    email = StringField('email: ', validators=[DataRequired(), Email('Illigal email')])
    username = StringField('username: ', validators=[DataRequired()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.select_by_email(field.data):
            raise ValidationError('Email address already used.')

class ResetPasswordForm(Form):
    password = PasswordField('password: ', validators=[DataRequired(), EqualTo('confirm_password', message='password not match')])
    confirm_password = PasswordField('confirm_password: ', validators=[DataRequired()])
    submit = SubmitField('Update password')

    def validate_password(self, field):
        if len(field.data) < 8:
            raise ValidationError('Too short. Password has to more than 8 characters')

class ForgotPasswordForm(Form):
    email = StringField('email: ', validators=[DataRequired(), Email()])
    submit = SubmitField('Update password')

    def validate_email(self, field):
        if not User.select_by_email(field.data):
            raise ValidationError('Email address is not registered')

class UserForm(Form):
    email = StringField('email: ', validators=[DataRequired(), Email('Illigal email')])
    username = StringField('username: ', validators=[DataRequired()])
    picture_path = FileField('update file')
    submit = SubmitField('Update information')

    def validate(self):
        if not super(Form, self).validate():
            return False
        user = User.select_by_email(self.email.data)
        if user:
            if user.id != int(current_user.get_id()):
                flash('Email address is already registered')
                return False
        return True

class ChangePasswordForm(Form):
    password = PasswordField('password: ', validators=[DataRequired(), EqualTo('confirm_password', message='password not match')])
    confirm_password = PasswordField('confirm_password: ', validators=[DataRequired()])
    submit = SubmitField('Update password')

    def validate_password(self, field):
        if len(field.data) < 8:
            raise ValidationError('Too short. Password has to more than 8 characters')


class UserSearchForm(Form):
    username = StringField('username: ', validators=[DataRequired()])
    submit = SubmitField('Search user')