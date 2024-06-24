# Standard library imports
import os
from datetime import datetime, timedelta
import json
# Django imports
from django.forms.models import model_to_dict
from django.http import response

# Local application/library specific imports
from auth import settings
from login.models import User
from . import crypto

# Third-party imports
import requests

duration = int(os.getenv("AUTH_LIFETIME", "10"))


def return_auth_cookie(user: User, full_response: response.HttpResponse):
    user_dict = model_to_dict(user, exclude=["password",
                                             "totp_key",
                                             "login_attempt",
                                             "totp_enabled"])
    expdate = datetime.now() + timedelta(minutes=duration)
    user_dict["exp"] = expdate
    user_dict["display_name"] = get_dn(user.id)
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

def get_dn(id: int):
    try:
        info_response = requests.get(f"{settings.USER_SERVICE_URL}/{id}/infos/",
                                data=None,
                                headers=None,
                                verify=False)
    except requests.exceptions.ConnectionError as e:
        print(e, flush=True)
        return response.HttpResponse(status=408, reason="Cant connect to user-service")

    if info_response.status_code == 200:
        print(f"{response.status_code}, {response.reason}", flush=True)
        return response.HttpResponse(status=response.status_code, reason=response.reason)

    data = info_response.json()
    return data["display_name"]
