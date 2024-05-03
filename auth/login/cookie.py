# Standard library imports
import os
from datetime import datetime, timedelta

# Django imports
from django.forms.models import model_to_dict
from django.http import response

# Local application/library specific imports
from login.models import User
from . import crypto

# Third-party imports

duration = int(os.getenv("AUTH_LIFETIME", "10"))


def return_auth_cookie(user: User, full_response: response.HttpResponse):
    user_dict = model_to_dict(user, exclude=["password",
                                             "totp_key",
                                             "login_attempt",
                                             "totp_enabled"])
    expdate = datetime.now() + timedelta(minutes=duration)
    user_dict["exp"] = expdate
    payload = crypto.encoder.encode(user_dict, "auth")
    full_response.set_cookie(key="auth_token",
                             value=payload,
                             secure=True,
                             httponly=True)
    full_response.set_cookie(key="user_id",
                             value=user.id,
                             secure=True)
    return full_response


def return_refresh_token(user: User):
    full_response = response.HttpResponse()
    full_response.set_cookie(key='refresh_token',
                             value=user.generate_refresh_token(),
                             secure=True,
                             httponly=True,
                             samesite="Strict")

    return return_auth_cookie(user, full_response)
