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
    user_dict = model_to_dict(new_user, exclude=["password",
                                             "totp_key",
                                             "login_attempt",
                                             "totp_enabled"])
    expdate = datetime.now() + timedelta(minutes=duration)
    user_dict["exp"] = expdate
    payload = crypto.encoder.encode(user_dict, "auth")
    update_request_cookie = {'refresh_token' : new_user.generate_refresh_token,
                             'auth_token' : payload}

    try:
        update_response = requests.post(f"{settings.USER_SERVICE_URL}/{new_user_id}/update",
                                        data=json.dumps(update_request_data),
                                        headers=headers,
                                        cookies=update_request_cookie
                                        verify=False)
    except requests.exceptions.ConnectionError as e:
        print(e)
        return response.HttpResponse(status=408, reason="Cant connect to user-service")

    if update_response.status_code != 200:
        return response.HttpResponse(status=update_response.status_code, reason=update_response.text)

    return update_response


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
