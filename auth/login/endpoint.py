from datetime import datetime, timedelta

from django.http import response
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET, require_http_methods
from django.forms.models import model_to_dict
from django.conf import settings
from django.core import exceptions
from login.models import User

import json
import jwt


def return_user_cookie(user, cookie_response):
    user_dict = model_to_dict(user)
    priv = settings.PRIVATE_KEY
    expdate = datetime.now() + timedelta(minutes=10)
    user_dict["exp"] = expdate
    payload = jwt.encode(user_dict, priv, algorithm="RS256")
    cookie_response.set_cookie("token", payload, max_age=None)
    return cookie_response


# Create your views here.

@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def login_endpoint(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponse(status=400, reason="Bad Json content: JSONDecodeError")

    expected_keys = {"login", "password"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponse(status=400, reason="Bad Json content: Bad Keys")

    login = data["login"]
    password = data["password"]

    try:
        user = User.objects.get(login=login)
    except exceptions.ObjectDoesNotExist:
        return response.HttpResponse(status=401, reason="f'User {username} does not exist")

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
        return response.HttpResponse(status=400, reason="Bad Json content: Decode Error")

    expected_keys = {"login", "password", "display_name"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponse(status=400, reason="Bad Json content: Bad Keys")

    login = data["login"]
    display_name = data["display_name"]
    password = data["password"]

    if User.objects.filter(login=login).exists():
        return response.HttpResponse(status=401, reason="User with this login already exists")

    new_user = User(login=login, password=password, displayName=display_name)
    new_user.save()

    cookie_response = response.JsonResponse({'refresh_token': new_user.generate_refresh_token()}, status=200)
    return return_user_cookie(new_user, cookie_response)

@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_GET
def refresh_auth_token(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponse(status=400, reason="Bad Json content: Decode Error")

    expected_key = {"refresh_token"}
    if set(data.keys()) != expected_key:
        return response.HttpResponse(status=400, reason="Bad Json content: Bad keys")

    token = data["refresh_token"]

    try:
        payload = jwt.decode(jwt=token, key=settings.PRIVATE_KEY, algorithms=["RS256"])
        user = User.objects.get(login=payload["user_id"])
        id = payload["id"]
    except (jwt.DecodeError, jwt.ExpiredSignatureError, exceptions.ObjectDoesNotExist, KeyError):
        return response.HttpResponse(status=443, reason="Invalid refresh Token")
    if id != user.jwt_emitted:
        return response.HttpResponse(status=443, reason="Invalid refresh Token")

    return return_user_cookie(user, response.HttpResponse(status=200))
