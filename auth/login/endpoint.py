from datetime import datetime, timedelta

from django.http import response
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
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
def login(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponse(status=400, reason="Bad Json content")

    expected_keys = {"username", "password"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponse(status=400, reason="Bad Json content")

    username = data["username"]
    password = data["password"]

    try:
        user = User.objects.get(login=username)
    except exceptions.ObjectDoesNotExist:
        return response.HttpResponse(status=401, reason="f'User {username} does not exist")

    if user.password == password:
        cookie_response = response.JsonResponse({'refresh_token': user.generate_refresh_token()}, status=200)
        return return_user_cookie(user, cookie_response)
    else:
        return response.HttpResponse(status=401, reason="Wrong password")




@csrf_exempt # TODO: DO NOT USE IN PRODUCTION
@require_GET
def refresh_token(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponse(status=400, reason="Bad Json content")

    expected_key = {"refresh_token"}
    if set(data.keys()) != expected_key:
        return response.HttpResponse(status=400, reason="Expected credential not foud")

    token = data["refresh_token"]

    try:
        payload = jwt.decode(jwt=token, key=settings.PRIVATE_KEY, algorithms=["RS256"])
        user = User.objects.get(login=payload["user_id"])
    except (jwt.DecodeError, jwt.ExpiredSignatureError, exceptions.ObjectDoesNotExist):
        return response.HttpResponse(status=400, reason="Invalid refresh Token")

    return return_user_cookie(user, response.HttpResponse(status=200))
