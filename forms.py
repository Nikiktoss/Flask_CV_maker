from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo


class LoginForm(FlaskForm):
    username = StringField("Username ")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=7, max=55)])
    submit = SubmitField("Login")


class SignUpForm(FlaskForm):
    username = StringField("Username ")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=7, max=55)])
    password2 = PasswordField("Repeat Password", validators=[DataRequired(),
                                                             EqualTo("password", message="Passwords are not equal")])
    submit = SubmitField("Sign Up")
