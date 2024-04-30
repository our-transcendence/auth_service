# Standard library imports
from datetime import datetime, timedelta
import base64
import binascii
import json
import os

# Django imports
from django.contrib.auth import hashers
from django.core import exceptions
from django.db import OperationalError, IntegrityError, DataError
from django.forms.models import model_to_dict
from django.http import response, HttpRequest, Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
# Third-party imports


# Local application/library specific imports
from login.models import User
from . import crypto
from .utils import send_new_user

import ourJWT.OUR_exception

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
    return full_response


def return_refresh_token(user: User):
    full_response = response.HttpResponse()
    full_response.set_cookie(key='refresh_token',
                             value=user.generate_refresh_token(),
                             secure=True,
                             httponly=True,
                             samesite="Strict")

    return return_auth_cookie(user, full_response)
