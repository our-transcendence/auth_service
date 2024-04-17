from datetime import datetime, timedelta

import ourJWT.OUR_exception
from django.http import response, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET, require_http_methods
from django.forms.models import model_to_dict
from django.shortcuts import get_object_or_404

from . import crypto
from django.core import exceptions
from login.models import User

import os

import json

from ourJWT import decorators

duration = int(os.getenv("AUTH_LIFETIME", "10"))


def return_auth_cookie(user: User, full_response: response.HttpResponse):
    user_dict = model_to_dict(user)
    expdate = datetime.now() + timedelta(seconds=5)
    user_dict["exp"] = expdate
    payload = crypto.encoder.encode(user_dict, "auth")
    full_response.set_cookie(key="auth_token", value=payload, secure=True, httponly=True)
    return full_response

def return_refresh_token(user: User):
    full_response = response.HttpResponse()
    full_response.set_cookie(key='refresh_token', value=user.generate_refresh_token(), secure=True, httponly=True)
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
    auth_type: str = auth.split(" ")[0]
    if auth_type != "Basic":
        return response.HttpResponseBadRequest(reason="invalid Authorization type")
    auth_data: str = auth.split(" ")[1]
    login = auth_data.split("/")[0]
    password = auth_data.split("/")[1]

    try:
        user: User = User.objects.get(login=login)
    except exceptions.ObjectDoesNotExist:
        return response.HttpResponse(status=401, reason='Invalid credential')

    if user.password == password:
        return return_refresh_token(user=user)
    else:
        return response.HttpResponse(status=401, reason='Invalid credential')


@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_POST
def register_endpoint(request: HttpRequest):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponse(status=400, reason="JSON Decode Error")

    expected_keys = {"login", "password", "display_name"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponse(status=400, reason="Bad Keys")

    login = data["login"]
    display_name = data["display_name"]
    password = data["password"]

    if User.objects.filter(login=login).exists():
        return response.HttpResponse(status=401, reason="User with this login already exists")

    new_user = User(login=login, password=password, displayName=display_name)
    new_user.save()

    return return_refresh_token(new_user)

@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def refresh_auth_token(request: HttpRequest, *args):
    try:
        request.COOKIES["auth_token"]
    except:
        return response.HttpResponseBadRequest(reason="no auth token")
    try:
        auth = ourJWT.Decoder.decode(request.COOKIES.get("auth_token"), check_date=False)
    except:
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
    user = get_object_or_404(User, pk=refresh_pk)

    if user.login != auth_login:
        return response.HttpResponseForbidden("token error")

    id = refresh["jti"]
    if id != user.jwt_emitted:
        return response.HttpResponseBadRequest(reason="token error")

    return return_auth_cookie(user, response.HttpResponse(status=200))


@ourJWT.Decoder.check_auth()
def test_decorator(request, **kwargs):
    auth = kwargs["token"]
    print(auth)
    return response.HttpResponse()
