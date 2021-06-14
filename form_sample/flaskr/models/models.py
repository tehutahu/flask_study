from datetime import datetime
from sqlalchemy import CheckConstraint
from flaskr.database import db


class Member(db.Model):
    __tablename__ = 'members'
    __table_args__ = (
        CheckConstraint('update_at >= create_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), index=True, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.String(20))
    create_at = db.Column(db.DateTime, nullable=False, default=datetime.now)
    update_at = db.Column(db.DateTime, nullable=False, default=datetime.now, onupdate=datetime.now)


    def __init__(self, name, age, comment):
        self.name = name
        self.age = age
        self.comment = comment