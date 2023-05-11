from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

import re


additional_symbols = r"@$!%*#?&[]().,+-=\/|"


class LoginForm(FlaskForm):
    username = StringField("Username ")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=55)])
    submit = SubmitField("Login")


class SignUpForm(FlaskForm):
    username = StringField("Username ")
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8, max=55, message="Password length "
                                                                                                   "should be from 8 "
                                                                                                   "to 55 symbols")])
    password2 = PasswordField("Repeat Password", validators=[DataRequired(),
                                                             EqualTo("password", message="Passwords are not equal")])
    submit = SubmitField("Sign Up")

    def validate_password(self, password):
        if str(password.data).isdigit():
            raise ValidationError("Password is numeric")

        digit_error = re.search(r"\d", password.data) is None
        lowercase_error = re.search(r"[a-z]", password.data) is None
        uppercase_error = re.search(r"[A-Z]", password.data) is None
        additional_symbol_error = True

        for symbol in password.data:
            if symbol in additional_symbols:
                additional_symbol_error = False
                break

        if digit_error or lowercase_error or uppercase_error or additional_symbol_error:
            raise ValidationError("Password is not strong")

        self.password = password
