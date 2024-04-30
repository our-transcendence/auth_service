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



# Create your views here.


@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_POST
def register_endpoint(request: HttpRequest):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponseBadRequest(reason="JSON Decode Error")

    expected_keys = {"login", "password", "display_name"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponseBadRequest(reason="Bad Keys")

    user_data = {
        "login": data["login"],
        "display_name": data["display_name"],
        "password": data["password"]
    }

    if user_data["password"].__len__() < 5:
        return response.HttpResponseBadRequest(reason="Invalid credential")
    if User.objects.filter(login=user_data["login"]).exists():
        return response.HttpResponseForbidden(reason="User with this login already exists")

    new_user = User(login=user_data["login"], password=user_data["password"], displayName=user_data["display_name"])
    try:
        new_user.save()
    except (IntegrityError, OperationalError) as e:
        print(e, flush=True)
        return response.HttpResponse(status=400, reason="Database Failure")

    try:
        new_user.clean_fields()
    except (exceptions.ValidationError, DataError) as e:
        print(e, flush=True)
        return response.HttpResponseBadRequest(reason="Invalid credential")

    send: response.HttpResponse = send_new_user(new_user, user_data)
    if send.status_code != 200:
        return send

    try:
        new_user.password = hashers.make_password(user_data["password"])
        new_user.save()
    except (IntegrityError, OperationalError) as e:
        print(f"DATABASE FAILURE {e}")
        # TODO: Send a request to delete user from user-service
        return response.HttpResponse(status=400, reason="Database Failure")

    return return_refresh_token(new_user)


@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def login_endpoint(request: HttpRequest):
    auth: str = request.headers.get("Authorization", None)
    if auth is None:
        return response.HttpResponseBadRequest(reason="No Authorization header found in request")

    auth_type: str = auth.split(" ", 1)[0]
    if auth_type != "Basic":
        return response.HttpResponseBadRequest(reason="invalid Authorization type")

    auth_data_encoded: str = auth.split(" ")[1]
    try:
        auth_data = base64.b64decode(auth_data_encoded).decode()
    except binascii.Error:
        return response.HttpResponseBadRequest(reason="invalid encoding")
    login = auth_data.split(":")[0]
    try:
        password = auth_data.split(":", 1)[1]
    except IndexError:
        return response.HttpResponse(status=401, reason='Invalid credential')
    try:
        user: User = User.objects.get(login=login)
    except exceptions.ObjectDoesNotExist:
        return response.HttpResponse(status=401, reason='Invalid credential')

    if not hashers.check_password(password, user.password):
        return response.HttpResponse(status=401, reason='Invalid credential')

    if not user.totp_enabled:
        return return_refresh_token(user=user)

    user.login_attempt = timezone.now()
    user.save()
    need_otp_response: response.HttpResponse = response.HttpResponse(status=202, reason="Expecting OTP")
    need_otp_response.set_cookie(key="otp_user_ID",
                                 value=user.id,
                                 httponly=True,
                                 max_age=timedelta(seconds=60))
    return need_otp_response


# Can't use the decorator as the auth token may be expired
@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def refresh_auth_token(request: HttpRequest):
    try:
        request.COOKIES["auth_token"]
    except KeyError:
        return response.HttpResponseBadRequest(reason="no auth token")
    try:
        auth = ourJWT.Decoder.decode(request.COOKIES.get("auth_token"), check_date=False)
    except (ourJWT.BadSubject, ourJWT.RefusedToken):
        return response.HttpResponseBadRequest(reason='bad auth token')
    auth_login = auth.get("login")

    try:
        request.COOKIES["refresh_token"]
    except KeyError:
        return response.HttpResponseBadRequest(reason="no refresh token")
    try:
        refresh = ourJWT.Decoder.decode(request.COOKIES.get("refresh_token"))
    except (ourJWT.ExpiredToken, ourJWT.RefusedToken, ourJWT.BadSubject):
        return response.HttpResponseBadRequest("decode error")

    refresh_pk = refresh.get("pk")
    try:
        user = get_object_or_404(User, pk=refresh_pk)
    except Http404:
        return response.Http404()
    if user.login != auth_login:
        return response.HttpResponseForbidden("token error")

    jwt_id = refresh["jti"]
    if jwt_id != user.jwt_emitted:
        return response.HttpResponseBadRequest(reason="token error")

    return return_auth_cookie(user, response.HttpResponse(status=200))
