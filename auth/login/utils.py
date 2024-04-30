# Standard library imports
from datetime import datetime, timedelta
import base64
import binascii
import json
import os

# Django imports
from django.conf import settings
from django.contrib.auth import hashers
from django.core import exceptions
from django.db import OperationalError, IntegrityError, DataError
from django.forms.models import model_to_dict
from django.http import response, HttpRequest, Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET, require_http_methods

# Third-party imports
import pyotp
import requests

# Local application/library specific imports
from login.models import User
from . import crypto
import ourJWT.OUR_exception

def get_user_from_jwt(kwargs):
    auth = kwargs["token"]
    key = auth["id"]
    user = get_object_or_404(User, pk=key)
    return user

def send_new_user(new_user: User, user_data: dict):
    new_user_id = new_user.id
    create_request_data = {"id": new_user_id, "login": user_data["login"]}
    headers = {'Content-Type': 'application/json'}
    try:
        create_response = requests.post(f"{settings.USER_SERVICE_URL}/register",
                                        data=json.dumps(create_request_data),
                                        headers=headers,
                                        verify=False)
    except requests.exceptions.ConnectionError as e:
        print(e)
        return response.HttpResponse(status=408, reason="Cant connect to user-service")

    if create_response.status_code != 200:
        return response.HttpResponse(status=create_response.status_code, reason=create_response.text)

    update_request_data = {"display_name": user_data["display_name"]}

    try:
        update_response = requests.post(f"{settings.USER_SERVICE_URL}/{new_user_id}/update",
                                        data=json.dumps(update_request_data),
                                        headers=headers,
                                        verify=False)
    except requests.exceptions.ConnectionError as e:
        print(e)
        return response.HttpResponse(status=408, reason="Cant connect to user-service")

    if update_response.status_code != 200:
        return response.HttpResponse(status=update_response.status_code, reason=update_response.text)

    return update_response

@require_GET
def pubkey_retrieval(request):
    return response.HttpResponse(crypto.PUBKEY)
