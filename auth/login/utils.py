# Standard library imports
import json

# Third-party imports
import requests
# Django imports
from django.conf import settings
from django.http import response
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_GET

# Local application/library specific imports
from login.models import User
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

    try:
        update_response = requests.post(f"{settings.USER_SERVICE_URL}/{new_user_id}/update",
                                        data=json.dumps(update_request_data),
                                        headers=headers,
                                        verify=False)
    except requests.exceptions.ConnectionError as e:
        print(e)
        return response.HttpResponse(status=408, reason="Cant connect to user-service")

    if update_response.status_code != 200:
        return response.HttpResponse(status=update_response.status_code, reason=update_response.text)

    return update_response


@require_GET
def pubkey_retrieval(request):
    return response.HttpResponse(crypto.PUBKEY)
