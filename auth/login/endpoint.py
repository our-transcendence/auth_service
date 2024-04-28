import binascii
from datetime import datetime, timedelta

from django.db import OperationalError, IntegrityError, DataError
from django.http import response, HttpRequest, Http404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET, require_http_methods
from django.forms.models import model_to_dict
from django.shortcuts import get_object_or_404
from django.core import exceptions
from django.contrib.auth import hashers
from django.utils import timezone


import ourJWT.OUR_exception

from . import crypto

from login.models import User
import base64
import os

import json

import pyotp

from django.conf import settings
import requests

duration = int(os.getenv("AUTH_LIFETIME", "10"))


def get_user_from_jwt(kwargs):
    auth = kwargs["token"]
    key = auth["id"]
    user = get_object_or_404(User, pk=key)
    return user


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


# Create your views here.

#TODO: ne pas envoyer le refresh token en body, mais en cookie http only : https://dev.to/bcerati/les-cookies-httponly-une-securite-pour-vos-tokens-2p8n
#TODO: get info in Authorization request header https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
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
      
    if  not hashers.check_password(password, user.password):
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

    login = data["login"]
    display_name = data["display_name"]
    password = data["password"]

    if password.__len__() < 5:
        return response.HttpResponseBadRequest(reason="Invalid credential")

    if User.objects.filter(login=login).exists():
        return response.HttpResponse(status=401, reason="User with this login already exists")

    try:
        new_user = User(login=login, password=password)
        new_user.clean_fields()
        new_user.save()
        new_user_id = new_user.id

        create_request_data = {"id:" : new_user_id, "login:" : login}
        create_response = requests.post(settings.USER_SERVICE_URL + "/register", create_request_data)
        if create_response.status_code != 200:
            new_user.delete()
            return response.HttpResponse(status=create_response.status_code, reason=create_response.text)

        update_request_data = {"display_name": display_name}
        update_response = requests.post(settings.USER_SERVICE_URL + "/" + new_user_id + "/update", update_request_data)
        if update_response.status_code != 200:
            new_user.delete()
            return response.HttpResponse(status=update_response.status_code, reason=update_response.text)
    except (IntegrityError, OperationalError) as e:
        print(f"DATABASE FAILURE {e}")
        return response.HttpResponse(status=500, reason="Database Failure")
    except (exceptions.ValidationError, DataError) as e:
        print(e)
        return response.HttpResponseBadRequest(reason="Invalid credential")
    except requests.exceptions.ConnectionError as e:
        new_user.delete()
        print(e)
        return response.HttpResponse(status=500, reason="Cant connect to user-service")
    new_user.password = hashers.make_password(password)
    new_user.save()
    return return_refresh_token(new_user)


#Can't use the decorator as the auth token may be expired
@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def refresh_auth_token(request: HttpRequest, *args):
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
    except:
        return response.HttpResponseBadRequest(reason="no refresh token")
    try:
        refresh = ourJWT.Decoder.decode(request.COOKIES.get("refresh_token"))
    except:
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


@csrf_exempt
@ourJWT.Decoder.check_auth()
@require_http_methods("PATCH")
def set_totp(request: HttpRequest, **kwargs):
    try:
        user = get_user_from_jwt(kwargs)
    except Http404:
        return response.HttpResponseNotFound("No user found with given ID")

    if user.totp_enabled is True:
        return response.HttpResponseForbidden(reason="2FA already enabled for the account")

    user.totp_key = pyotp.random_base32()
    user.login_attempt = timezone.now()
    user.save()
    response_content = {"totp_key": user.totp_key,
                        "Key Uri Format":
                            f"otpauth://totp/OUR_Transcendence:{user.login}"
                            "?secret={user.totp_key}"
                            "&issuer=OUR_Transcendence-auth"}
    return response.JsonResponse(response_content, status=202, reason="Expecting OTP")

@csrf_exempt
@require_POST
def otp_submit(request: HttpRequest):
    auth_token = request.COOKIES.get("auth_token")
    if auth_token is None: # pas de token Auth donne, le user n'est pas connecte
        user_id = request.COOKIES.get("otp_user_ID")
        if user_id is None:
            return response.HttpResponseBadRequest()
        try :
            user = get_object_or_404(User, pk=user_id)
        except Http404:
            return response.HttpResponseNotFound("no user found with given ID")
    else:
        try:
            auth = ourJWT.Decoder.decode(auth_token)
        except (ourJWT.BadSubject, ourJWT.RefusedToken, ourJWT.ExpiredToken):
            return response.HttpResponseBadRequest(reason='bad auth token')
        try:
            user = get_user_from_jwt({"token":auth})
        except Http404:
            return response.HttpResponseNotFound("no user found with given ID")

    if user.totp_key is None:
        return response.HttpResponse(status=412, reason="OTP not set up for user")
    if not request.body:
        user.totp_key = None
        user.save()
        return response.HttpResponseBadRequest(reason="empty request")

    user_code = json.loads(request.body).get("otp_code")
    if user_code is None:
        if not user.totp_enabled:
            user.totp_key = None
            user.save()
        return response.HttpResponseBadRequest(reason="No otp in request")
    if (user.login_attempt + timedelta(minutes=1)) < timezone.now():
        if not user.totp_enabled:
            user.totp_key = None
            user.save()
        return response.HttpResponseForbidden(reason="OTP validation timed out")

    user.login_attempt = None
    if not user.totp_item.verify(user_code):
        user.save()
        return response.HttpResponseForbidden(reason="Bad OTP")

    if not user.totp_enabled:
        user.totp_enabled = True
        user.save()
        return response.HttpResponse()
    user.save()
    return return_refresh_token(user=user)



@ourJWT.Decoder.check_auth()
def test_decorator(request, **kwargs):
    auth = kwargs["token"]
    print(auth)
    return response.HttpResponse()


@require_GET
def pubkey_retrieval(request):
    return response.HttpResponse(crypto.PUBKEY)
