from datetime import datetime, timedelta
from uuid import uuid4

from flask_bcrypt import generate_password_hash, check_password_hash
from flask_login import UserMixin, current_user
from sqlalchemy.orm import aliased
from sqlalchemy import and_, or_

from flaskr import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

class User(UserMixin, db.Model):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False , index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password = db.Column(db.String(128), default=generate_password_hash('snsflaskapp'), nullable=False)
    picture_path = db.Column(db.Text)
    is_active = db.Column(db.Boolean, unique=False, default=False)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    def __init__(self, email, username):
        self.email = email
        self.username = username

    def validate_password(self, password):
        return check_password_hash(self.password, password)

    def add_user(self):
        with db.session.begin(subtransactions=True):
            db.session.add(self)
        db.session.commit()

    @classmethod
    def select_by_email(cls, email):
       return cls.query.filter_by(email=email).first()
    
    @classmethod
    def select_by_id(cls, id):
       return cls.query.get(id)

    # Outer join UserConnect
    @classmethod
    def search_by_name(cls, username):
        user_connect1 = aliased(UserConnect)
        user_connect2 = aliased(UserConnect)

        return cls.query.filter(
            cls.username.like(f'%{username}%'),
            cls.id != int(current_user.get_id()),
            cls.is_active == True
        ).outerjoin(
            user_connect1,
            and_(
                user_connect1.from_user_id == cls.id,
                user_connect1.to_user_id == current_user.get_id()
            )
        ).outerjoin(
            user_connect2,
            and_(
                user_connect2.from_user_id == current_user.get_id(),
                user_connect2.to_user_id == cls.id                
            )
        ).with_entities(
            cls.id, cls.username, cls.picture_path,
            user_connect1.status.label("joined_status_to_from"),
            user_connect2.status.label("joined_status_from_to")
        ).all()

    @classmethod
    def select_friends(cls):
        UC = aliased(UserConnect)
        return cls.query.filter(
            UC.status == UserConnect.condition2status['accept']
            ).join(
                UC,
                or_(
                    and_(
                        cls.id == UC.from_user_id,
                        UC.to_user_id == current_user.get_id()
                    ),
                    and_(
                        cls.id == UC.to_user_id,
                        UC.from_user_id == current_user.get_id()
                    )
                )
            ).with_entities(
                cls.id, cls.username, cls.picture_path
            ).all()

    @classmethod
    def select_requesting(cls):
        UC = aliased(UserConnect)
        return cls.query.filter(
            UC.status == UserConnect.condition2status['request']
            ).join(
                UC,
                and_(
                    cls.id == UC.to_user_id,
                    UC.from_user_id == current_user.get_id()
                )
            ).with_entities(
                cls.id, cls.username, cls.picture_path
            ).all()

    @classmethod
    def select_requested(cls):
        UC = aliased(UserConnect)
        return cls.query.filter(
            UC.status == UserConnect.condition2status['request']
            ).join(
                UC,
                and_(
                    cls.id == UC.from_user_id,
                    UC.to_user_id == current_user.get_id()
                )
            ).with_entities(
                cls.id, cls.username, cls.picture_path
            ).all()

    def save_new_password(self, new_password):
        self.password = generate_password_hash(new_password)
        self.is_active = True


class PasswordResetToken(db.Model):

    __tablename__ = 'password_reset_tokens'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), server_default=str(uuid4), unique=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    expire_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    def __init__(self, token, user_id, expire_at):
        self.token = token
        self.user_id = user_id
        self.expire_at = expire_at

    @classmethod
    def publish_token(cls, user):
        token = str(uuid4())
        new_token = cls(
            token,
            user.id,
            datetime.now() + timedelta(days=1)
        )
        with db.session.begin(subtransactions=True):
            db.session.add(new_token)
        db.session.commit()
        return token

    @classmethod
    def get_user_id_by_token(cls, token):
        now = datetime.now()
        record = cls.query.filter_by(token=str(token)).filter(cls.expire_at > now).first()
        if record:
            return record.user_id
        else:
            return None

    @classmethod
    def delete_token(cls, token): 
        cls.query.filter_by(token=str(token)).delete()


class UserConnect(db.Model):
    '''
    status
        1: Requesting
        2: Friend
        -1: Blocking
    '''
    
    __tablename__ = 'user_connects'

    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    status = db.Column(db.Integer, unique=False, default=1)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    condition2status = {
        'accept'  : 2,
        'request' : 1,
        'reject'  : 0,
        'remove'  : 0,
        'blocking':-1,
        'blocked' :-2
    }

    def __init__(self, from_user_id, to_user_id):
        self.from_user_id = from_user_id
        self.to_user_id = to_user_id

    @classmethod
    def get_connect_by_ids(cls, from_user_id, to_user_id):
        return cls.query.filter_by(from_user_id=from_user_id, to_user_id=to_user_id).first()

    @classmethod
    def request_connect(cls, from_user_id, to_user_id):
        return cls._update_connect(from_user_id, to_user_id, status=cls.condition2status['request'])
        
    @classmethod
    def accept_connect(cls, from_user_id, to_user_id):
        return cls._update_connect(from_user_id, to_user_id, status=cls.condition2status['accept'])

    @classmethod
    def reject_connect(cls, from_user_id, to_user_id):
        return cls._update_connect(from_user_id, to_user_id, status=cls.condition2status['reject'])
    
    @classmethod
    def remove_connect(cls, current_user_id, opponent_id):
        is_success1 = cls._update_connect(current_user_id, opponent_id, status=cls.condition2status['remove'])
        is_success2 = cls._update_connect(opponent_id, current_user_id, status=cls.condition2status['remove'])
        return is_success1 and is_success2

    @classmethod
    def block_connect(cls, current_user_id, opponent_id):
        is_success1 = cls._update_connect(current_user_id, opponent_id, status=cls.condition2status['blocking'])
        is_success2 = cls._update_connect(opponent_id, current_user_id, status=cls.condition2status['blocked'])
        return is_success1 and is_success2

    @classmethod
    def delete_connect(cls, id):
        with db.session.begin(subtransactions=True):
            cls.query.filter_by(id=id).delete()
        db.session.commit()
    
    @classmethod
    def _update_connect(cls, from_user_id, to_user_id, status):
        target_connect = cls.get_connect_by_ids(from_user_id=from_user_id, to_user_id=to_user_id)
        if not target_connect:
            target_connect = cls(
                from_user_id=from_user_id, 
                to_user_id=to_user_id
            )
            target_connect.add_connect()
        target_connect.update_status(status=status)
        is_success = status == target_connect.status
        return is_success

    @classmethod
    def update_condition(cls, opponent_id, condition):
        '''
        condition:
            request: Request from current user to opponent
            accept : Accept from opponent to current user
            reject : Reject from opponent to current user
            remove : Remove connection both from and to
            block  : Block from current user to opponent
        '''

        is_success = False
        if condition == 'request':
            is_success = cls.request_connect(
                from_user_id=current_user.get_id(),
                to_user_id=opponent_id
            )
        elif condition == 'accept':
            is_success = cls.accept_connect(
                from_user_id=opponent_id,
                to_user_id=current_user.get_id()
            )
        elif condition == 'reject':
            is_success = cls.reject_connect(
                from_user_id=opponent_id,
                to_user_id=current_user.get_id()
            )
        elif condition == 'remove':
            is_success = cls.remove_connect(
                current_user_id=current_user.get_id(),
                opponent_id=opponent_id
            )
        elif condition == 'block':
            is_success = cls.block_connect(
                current_user_id=current_user.get_id(),
                opponent_id=opponent_id
            )
        return is_success

    @classmethod
    def is_friend(cls, opponent_id):
        user = cls.query.filter(
            or_(
                and_(
                    cls.from_user_id == opponent_id,
                    cls.to_user_id == current_user.get_id(),
                    cls.status == 2
                ),
                and_(
                    cls.from_user_id == current_user.get_id(),
                    cls.to_user_id == opponent_id ,
                    cls.status == 2
                )
            )
        ).first()
        return True if user else False

    def add_connect(self):
        with db.session.begin(subtransactions=True):
            db.session.add(self)
        db.session.commit()
    
    def update_status(self, status):
        with db.session.begin(subtransactions=True):
            self.status = status
            self.update_at = datetime.now()
        db.session.commit()
    
class Message(db.Model):

    __tablename__ = 'messages'

    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    is_read = db.Column(db.Boolean, default=False)
    message = db.Column(db.Text)
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)

    def __init__(self, from_user_id, to_user_id, message):
        self.from_user_id = from_user_id
        self.to_user_id = to_user_id
        self.message = message

    def add_message(self):
        with db.session.begin(subtransactions=True):
            db.session.add(self)
        db.session.commit()

    @classmethod
    def _get_friend_messages(cls, opponent_id):
        return cls.query.filter(
            or_(
                and_(
                    cls.from_user_id == current_user.get_id(),
                    cls.to_user_id == opponent_id
                    ),
                and_(
                    cls.to_user_id == current_user.get_id(),
                    cls.from_user_id == opponent_id
                    )
            )
        ).order_by(cls.id).all()
    
    @classmethod
    def update_is_read_by_ids(cls, ids):
        with db.session.begin(subtransactions=True):
            cls.query.filter(
                cls.id.in_(ids)
                ).update(
                    {'is_read': 1},
                    synchronize_session='fetch'
                )
        db.session.commit()

    @classmethod
    def get_friend_messages(cls, opponent_id):
        messages = cls._get_friend_messages(opponent_id)
        read_ids = [message.id for message in messages if not message.is_read and message.from_user_id == opponent_id]
        cls.update_is_read_by_ids(read_ids)
        return messages

    @classmethod
    def select_not_read_messages(cls, from_user_id, to_user_id):
        return cls.query.filter(
            and_(
                cls.from_user_id == from_user_id,
                cls.to_user_id == to_user_id,
                cls.is_read == 0
            )
        ).order_by(cls.id).all()