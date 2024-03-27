from django.http import response
from django.views.decorators.csrf import csrf_exempt

from login.models import User

import json


def return_user_cookie(user):
    cookie_response = response.HttpResponse(status=200)
    cookie_response.set_cookie("user", user.login, max_age=None)
    return cookie_response


# Create your views here.


@csrf_exempt  # TODO: DO NOT USE IN PRODUCTION
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data["username"]
        password = data["password"]
        try:
            logged = User.objects.get(login=username)
        except User.DoesNotExist:
            return response.JsonResponse({'error_type': f'User {username} does not exist'}, status=401)
        if logged.password == password:
            return return_user_cookie(logged)
        else:
            return response.JsonResponse({'error_type': "bad password"}, status=401)
    else:
        return response.JsonResponse({'error_type': 'This endpoint can only be reached using POST method'}, status=405)
