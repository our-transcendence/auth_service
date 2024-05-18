# Standard library imports
import json
from datetime import datetime, timedelta

# Third-party imports
import requests
# Django imports
from django.conf import settings
from django.http import response
from django.shortcuts import get_object_or_404
from django.forms.models import model_to_dict


# Local application/library specific imports
from login.models import User
from login.cookie import duration
from . import crypto

def get_user_from_jwt(kwargs):
    auth = kwargs["token"]
    key = auth["id"]
    user = get_object_or_404(User, pk=key)
    return user


def send_new_user(new_user: User, user_data: dict):
    new_user_id = new_user.id
    create_request_data = {"id": new_user_id,
                           "login": user_data["login"],
                           "display_name": user_data["display_name"]}
    headers = {'Authorization': crypto.SERVICE_KEY,
               'Content-Type': 'application/json'}
    try:
        create_response = requests.post(f"{settings.USER_SERVICE_URL}/register/",
                                        data=json.dumps(create_request_data),
                                        headers=headers,
                                        verify=False)
    except requests.exceptions.ConnectionError as e:
        print(e)
        return response.HttpResponse(status=408, reason="Cant connect to user-service")

    if create_response.status_code != 200:
        print(f"{create_response.status_code}, {create_response.reason}", flush=True)

    return create_response


def get_42_login_from_token(access_token):
    # try request to api with the token
    try:
        profile_request_header = {"Authorization": f"Bearer {access_token}"}
        profile_response = requests.get("https://api.intra.42.fr/v2/me", headers=profile_request_header)
    except requests.exceptions.RequestException:
        return None, response.HttpResponse(status=500, reason="Cant connect to 42 api")

    if profile_response.status_code != 200:
        return None, response.HttpResponse(status=profile_response.status_code,
                                           reason=f"Error: {profile_response.status_code}")
    # get the login
    try:
        data = json.loads(profile_response.text)
    except json.JSONDecodeError:
        return None, response.HttpResponseBadRequest(reason="JSON Decode Error")
    login_42 = data.get("login")
    if login_42 is None:
        return None, response.HttpResponseBadRequest(reason="JSON Decode Error")
    return login_42, None
