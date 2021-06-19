from flask import (
    Blueprint, abort, request, render_template, redirect, url_for, flash, jsonify
)
from flask_login import login_user, login_required, logout_user
from flaskr.models import (
    User, PasswordResetToken, 
)
from flaskr.forms import LoginForm, RegisterForm, ResetPasswordForm
from flaskr import db


bp = Blueprint('app', __name__, url_prefix='')

@bp.route('/')
def home():
    return render_template('home.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('app.home'))

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User.select_by_email(form.email.data)
        if user and user.is_active and user.validate_password(form.password.data):
            login_user(user, remember=True)
            next = request.args.get('next')
            if not next:
                next = url_for('app.home')
            return redirect(next)
        elif not user:
            flash('User does not exist')
        elif not user.is_active:
            flash('User not active. Set password again')
        elif not user.validate_password(form.password.data):
            flash('Email and password are not match')
    return render_template('login.html', form=form)

@bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(
            email=form.email.data,
            username=form.username.data,
        )
        user.add_user()
        token = PasswordResetToken.publish_token(user)
        print(f'Password set URL: http://127.0.0.1:5000/reset_password/{token}')
        flash('Send password set URL')
        return redirect(url_for('app.login'))
    return render_template('register.html', form=form)

@bp.route('/reset_password/<uuid:token>', methods=['GET', 'POST'])
def reset_password(token):
    form = ResetPasswordForm(request.form)
    reset_user_id = PasswordResetToken.get_user_id_by_token(token)
    if not reset_user_id:
        abort(500)
    if request.method == 'POST' and form.validate():
        password = form.password.data
        user = User.select_by_id(reset_user_id)
        with db.session.begin(subtransactions=True):
            user.save_new_password(password)
            PasswordResetToken.delete_token(token)
        db.session.commit()
        flash('Updated password')
        return redirect(url_for('app.login'))
    return render_template('reset_password.html', form=form)