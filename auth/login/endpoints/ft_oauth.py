# Standard library imports
import json

import ourJWT.OUR_exception
# Third-party imports
import requests
# Django imports
from django.http import response, HttpRequest, Http404
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET

from auth import settings
# Local application/library specific imports
from login.models import User
from ..utils import get_user_from_jwt
from ..cookie import return_refresh_token

@csrf_exempt
@require_GET
# return the url to contact when asking for a 42 auth
def login_42_page(request: HttpRequest):
    return response.HttpResponse(settings.LOGIN_42_PAGE_URL)


@csrf_exempt
@require_GET
def get_token_42(request: HttpRequest):
    ft_code = request.COOKIES.get("code")
    if ft_code is None:
        return response.HttpResponseBadRequest(reason="no 42 oauth code in request")

    post_data = {
        "grant_type": "authorization_code",
        "client_id": settings.API_42_UID,
        "client_secret": settings.API_42_SECRET,
        "redirect_uri": settings.API_42_REDIRECT_URI,
        "code": ft_code,
    }

    try:
        oauth_response = requests.post("https://api.intra.42.fr/oauth/token", data=post_data)
    except requests.exceptions.ConnectionError:
        return response.HttpResponse(status=503, reason="Cant connect to 42 api")
    if oauth_response.status_code != 200:
        return response.HttpResponse(status=oauth_response.status_code,
                                     reason=f"Error: {oauth_response.status_code}, {oauth_response.text}")

    access_token = oauth_response.json().get("access_token")
    full_response = response.HttpResponse()
    full_response.set_cookie("access_token", access_token)
    return full_response


@csrf_exempt
@require_GET
def login_42_endpoint(request: HttpRequest):
    access_token = request.COOKIES.get("access_token")
    if access_token is None:
        return response.HttpResponseBadRequest(reason="no 42 token in request")

    login_42, http_error = get_42_login(access_token)
    if login_42 is None:
        return http_error

    try:
        user: User = User.objects.get(login_42__exact=login_42)
    except User.DoesNotExist:
        return response.HttpResponseBadRequest(reason="There is no account associated with this 42 account")
    return return_refresh_token(user)


@csrf_exempt
@require_POST
@ourJWT.Decoder.check_auth()
def link_42(request: HttpRequest, **kwargs):
    # check access_token
    access_token = request.COOKIES.get("access_token")
    if access_token is None:
        return response.HttpResponseBadRequest(reason="no 42 token in request")

    # check auth_token for our_transcendence
    # TODO: get auth token from kwargs
    try:
        user = get_user_from_jwt(kwargs)
    except Http404:
        return response.HttpResponseBadRequest(reason="no user corresponding to auth token")
    try:
        request.COOKIES["auth_token"]
    except KeyError:
        return response.HttpResponseBadRequest(reason="no auth token")
    try:
        auth = ourJWT.Decoder.decode(request.COOKIES.get("auth_token"), check_date=False)
    except (ourJWT.BadSubject, ourJWT.RefusedToken):
        return response.HttpResponseBadRequest(reason='bad auth token')
    auth_login = auth.get("login")

    if not User.objects.filter(login=auth_login).exists():
        return response.HttpResponseBadRequest(reason="There is no account associated with this 42 account")
    user = User.objects.filter(login=User.objects.filter(login=auth_login))[0]
    if user.login_42 is not None:
        return response.HttpResponseBadRequest(reason="There is already a 42 account associated with this account")

    login_42, http_error = get_42_login(access_token)
    if login_42 is None:
        return http_error

    user.login_42 = login_42
    # TODO: call User.save in a try except in case of DB failure
    return response.HttpResponse(status=204, reason="42 account linked successfully")


def get_42_login(access_token):
    # try request to api with the token
    try:
        profile_request_header = {"Authorization": f"Bearer {access_token}"}
        profile_response = requests.get("https://api.intra.42.fr/v2/me", headers=profile_request_header)
    except requests.exceptions.RequestException:
        return None, response.HttpResponse(status=408, reason="Cant connect to 42 api")

    if profile_response.status_code != 200:
        return None, response.HttpResponse(status=profile_response.status_code,
                                           reason=f"Error: {profile_response.status_code}")
    # get the login
    try:
        data = json.loads(profile_response.text)
    except json.JSONDecodeError:
        return None, response.HttpResponseBadRequest(reason="JSON Decode Error")
    login_42 = data["login"]
    return login_42, None
