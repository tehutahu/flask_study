from wtforms.form import Form
from wtforms import (
    StringField, IntegerField, TextField, HiddenField, SubmitField
)
import wtforms.validators as V


class CreateForm(Form):
    name = StringField('name: ', validators=[V.DataRequired('Input name.')])
    age = IntegerField('age: ', validators=[V.NumberRange(0, 100, 'Illigal range')])
    comment = TextField('comment: ')
    submit = SubmitField('Create')

class UpdateForm(Form):
    id = HiddenField()
    name = StringField('name: ', validators=[V.DataRequired('Input name.')])
    age = IntegerField('age: ', validators=[V.NumberRange(0, 100, 'Illigal range')])
    comment = TextField('comment: ')
    submit = SubmitField('Update')

class DeleteForm(Form):
    id = HiddenField()
    submit = SubmitField('Delete')
