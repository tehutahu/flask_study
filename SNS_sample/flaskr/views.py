import os
from datetime import datetime
from flask import (
    Blueprint, abort, request, render_template, redirect, url_for, flash, jsonify, current_app
)
from flask_login import login_user, login_required, logout_user, current_user
from flaskr.models import (
    User, PasswordResetToken, 
)
from flaskr.forms import (
    LoginForm, RegisterForm, ResetPasswordForm, ForgotPasswordForm, UserForm, ChangePasswordForm, UserSearchForm
)
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
                flash('welcome')
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

@bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        email = form.email.data
        user = User.select_by_email(email)
        if user:
            token = PasswordResetToken.publish_token(user)
            print(f'Password set URL: http://127.0.0.1:5000/reset_password/{token}')
            flash('Send password set URL')
        else:
            flash('User is not exist')
    return render_template('forgot_password.html', form=form)

@bp.route('/user', methods=['GET', 'POST'])
@login_required
def user():
    form = UserForm(request.form)
    if request.method == 'POST' and form.validate():
        user_id = current_user.get_id()
        user = User.select_by_id(user_id)
        with db.session.begin(subtransactions=True):
            user.username = form.username.data
            user.email = form.email.data
            file = request.files[form.picture_path.name].read()
            if file:
                if user.picture_path:
                    try:
                        os.remove(os.path.join(current_app.config['STATIC'], user.picture_path))
                    except FileNotFoundError as e:
                        print(e)
                filename = user_id + '_' + \
                    str(int(datetime.now().timestamp())) + '.jpg'
                user.picture_path = os.path.join(current_app.config['IMG_DIR'], filename)
                picture_path = os.path.join(current_app.config['STATIC'], user.picture_path)
                open(picture_path, 'wb').write(file)
        db.session.commit()
        flash('Success updated')
        return redirect(url_for('app.home'))
    return render_template('user.html', form=form)

@bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        user_id = current_user.get_id()
        user = User.select_by_id(user_id)
        with db.session.begin(subtransactions=True):
            password = form.password.data
            user.save_new_password(password)
        db.session.commit()
        flash('Updated password')
        return redirect(url_for('app.user'))
    return render_template('change_password.html', form=form)

@bp.route('/user_search', methods=['GET', 'POST'])
def user_search():
    form = UserSearchForm(request.form)
    users = None
    if request.method == 'POST' and form.validate():
        username = form.username.data
        users = User.search_by_name(username)
    return render_template(
        'user_search.html', form=form, users=users
    )

@bp.app_errorhandler(404)
def page_not_found(e):
    return redirect(url_for('app.home'))

@bp.app_errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500

