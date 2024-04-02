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


def return_user_cookie(user):
    user_dict = model_to_dict(user)
    priv = settings.PRIVATE_KEY
    expdate = datetime.now() + timedelta(minutes=10)
    user_dict["exp"] = expdate
    payload = jwt.encode(user_dict, priv, algorithm="RS256")
    cookie_response = response.HttpResponse(status=200)
    cookie_response.set_cookie("token", payload, max_age=None)
    return cookie_response


# Create your views here.


@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
@require_POST
def login(request):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponse(status=400, reason="Bad Json content")

    expected_keys = {"username", "password"}
    if set(data.keys()) != expected_keys:
        return response.JsonResponse({'error_type': "BAD Json Content"}, status=400)

    username = data["username"]
    password = data["password"]

    try:
        user = User.objects.get(login=username)
    except exceptions.ObjectDoesNotExist:
        return response.JsonResponse({'error_type': f'User {username} does not exist'}, status=401)

    if user.password == password:
        return return_user_cookie(user)
    else:
        return response.JsonResponse({'error_type': "bad password"}, status=401)
