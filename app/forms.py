from flask_wtf import FlaskForm

from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField, validators, widgets,fields, SelectMultipleField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_wtf.file import FileField, FileRequired, FileAllowed
from app.models import User, tags_query
import json
import ast
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()],render_kw={"placeholder": "username"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"placeholder": "password"})
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"placeholder": "username"})
    email = StringField('Email', validators=[DataRequired(), validators.Length(1, 64), Email()],render_kw={"placeholder": "admin@admin.ru"})
    password = PasswordField('Password', validators=[DataRequired()],render_kw={"placeholder": "password"})
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')], render_kw={"placeholder": "password"})
    submit = SubmitField('Register')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data.lower()).first():
            raise ValidationError('Email already registered.')


class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    password2 = PasswordField(
        'Repeat Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset')

class UploadForm(FlaskForm):
    file = FileField(validators=[FileAllowed(['png', 'jpeg', 'jpg'], 'Image Only!'), FileRequired('Choose a file!')])
    submit = SubmitField('Upload')


class Select2MultipleField(SelectMultipleField):

    def pre_validate(self, form):
        # Prevent "not a valid choice" error
        pass

    def process_formdata(self, valuelist):
        if valuelist:
            self.data = ",".join(valuelist)
        else:
            self.data = ''


class ChoiceForm(FlaskForm):
    a=[]
    try:
        lst = str(tags_query())
        a = ast.literal_eval(lst)#костыль, так как при обработки в шаблоне, ругается на Tag
    except ValueError:
        from app.commands import init_db
        init_db.create_users()

    multi_select = Select2MultipleField('test_form', [],
            choices=a,
            #choices=tags_query,
            description=u"name",
            render_kw={"multiple": "multiple"})