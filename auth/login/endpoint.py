from datetime import datetime, timedelta

from django.http import response, HttpRequest
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET, require_http_methods
from django.forms.models import model_to_dict

from . import crypto
from django.core import exceptions
from login.models import User

import os

import json

from ourJWT import decorators

duration = int(os.getenv("AUTH_LIFETIME", "10"))


def return_user_cookie(user, cookie_response):
    user_dict = model_to_dict(user)
    expdate = datetime.now() + timedelta(minutes=duration)
    user_dict["exp"] = expdate
    payload = crypto.encoder.encode(user_dict, "auth")
    cookie_response.set_cookie("auth_token", payload, max_age=None, Http_only=True)
    return cookie_response


# Create your views here.


#TODO: ne pas envoyer le refresh token en body, mais en cookie http only
@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def login_endpoint(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponse(status=400, reason="JSON Decode Error")

    expected_keys = {"login", "password"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponse(status=400, reason="Bad Keys")

    login = data["login"]
    password = data["password"]

    try:
        user = User.objects.get(login=login)
    except exceptions.ObjectDoesNotExist:
        return response.HttpResponse(status=401, reason=f'User \"{login}\" does not exist')

    if user.password == password:
        cookie_response = response.JsonResponse({'refresh_token': user.generate_refresh_token()}, status=200)
        return return_user_cookie(user, cookie_response)
    else:
        return response.HttpResponse(status=401, reason="Wrong password")

@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_POST
def register_endpoint(request):
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

    return response.JsonResponse({'refresh_token': new_user.generate_refresh_token()}, status=200)


#TODO: Check if auth token is in request, refuse if not the case
@decorators.auth_required(crypto.decoder)
@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def refresh_auth_token(request: HttpRequest):
    # auth: str = request.headers["Authorization"]
    # auth_type = auth.split(" ")[0]
    # auth_cred = auth.split(" ")[1]
    #
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponseBadRequest(reason="JSON Decode Error")

    expected_key = {"refresh_token"}
    if set(data.keys()) != expected_key:
        return response.HttpResponseBadRequest(reason="Bad keys")

    token = data["refresh_token"]

    try:
        payload = crypto.decoder.decode(token)
        # payload = jwt.decode(jwt=token, key=settings.PRIVATE_KEY, algorithms=["RS256"])
        user = User.objects.get(login=payload["user_id"])
        id = payload["id"]
    # except (jwt.DecodeError, jwt.ExpiredSignatureError, exceptions.ObjectDoesNotExist, KeyError):
    #     return response.HttpResponseBadRequest(reason="Invalid refresh Token")
    if id != user.jwt_emitted:
        return response.HttpResponseBadRequest(reason="Invalid refresh Token")

    return return_user_cookie(user, response.HttpResponse(status=200))
