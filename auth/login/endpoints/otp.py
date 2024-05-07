# Standard library imports
from datetime import timedelta
import json

from django.db import IntegrityError, OperationalError
# Django imports
from django.http import response, HttpRequest, Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_http_methods

# Third-party imports
import pyotp

# Local application/library specific imports
from login.models import User
from ..utils import get_user_from_jwt
from ..cookie import return_refresh_token
import ourJWT.OUR_exception


@csrf_exempt
@ourJWT.Decoder.check_auth()
@require_http_methods(["PATCH"])
def set_totp(request: HttpRequest, **kwargs):
    try:
        user = get_user_from_jwt(kwargs)
    except Http404:
        return response.HttpResponseNotFound("No user found with given ID")

    if user.totp_enabled is True:
        return response.HttpResponseForbidden(reason="2FA already enabled for the account")

    user.totp_key = pyotp.random_base32()
    user.login_attempt = timezone.now()
    user.save()
    response_content = {"totp_key": user.totp_key,
                        "uri_key":
                            f"otpauth://totp/OUR_Transcendence:{user.login}"
                            f"?secret={user.totp_key}"
                            "&issuer=OUR_Transcendence-auth"}
    return response.JsonResponse(response_content, status=202, reason="Expecting OTP")


@csrf_exempt
@require_POST
def otp_submit(request: HttpRequest):
    reason = request.COOKIES.get("otp_status")
    match reason:
        case "otp_login":
            return otp_login(request)
        case "otp_enable":
            return otp_enable(request)
        case "otp_disable":
            return otp_disable(request)
        case _:
            return response.HttpResponseBadRequest("no reason given for otp")

@csrf_exempt
@ourJWT.Decoder.check_auth()
@require_http_methods(["PATCH"])
def remove_totp(request: HttpRequest, **kwargs):
    try:
        user: User = get_user_from_jwt(kwargs)
    except Http404:
        return response.HttpResponseNotFound("no user found with given ID")

    if user.totp_enabled is False:
        return response.HttpResponseBadRequest("TOTP isn't enabled for given user")

    user.login_attempt = timezone.now()
    user.save()  # TODO: protect this in all file
    return response.HttpResponse(status=202, reason="Expecting otp")


def otp_login(request: HttpRequest):
    user_id = request.COOKIES.get("otp_user_ID")
    if user_id is None:
        return response.HttpResponseBadRequest()
    try:
        user = get_object_or_404(User, pk=user_id)
    except Http404:
        return response.HttpResponseNotFound("no user found with given ID")
    if user.totp_key is None:
        return response.HttpResponse(status=412, reason="OTP not set up for user")

    if not request.body:
        user.totp_key = None
        user.save()
        return response.HttpResponseBadRequest(reason="empty request")

    otp = get_otp_from_body(request.body)
    if otp is None:
        return response.HttpResponseBadRequest(reason="No otp in request")

    otp_status, otp_response = check_otp(user, otp)

    if otp_status is False:
        return otp_response

    user.login_attempt = None
    try:
        user.save()
    except (IntegrityError, OperationalError) as e:
        print(e, flush=True)
        return response.HttpResponse(status=400, reason="Database Failure")
    return return_refresh_token(user)

@ourJWT.Decoder.check_auth()
def otp_enable(request: HttpRequest, **kwargs):
    try:
        user = get_user_from_jwt(kwargs)
    except Http404:
        return response.HttpResponseBadRequest("No user found with given ID")

    if user.totp_enabled:
        # TODO finish here


def check_otp(user: User, otp: str):
    if (user.login_attempt + timedelta(minutes=1)) < timezone.now():
        return False, response.HttpResponseForbidden(reason="OTP validation timed out")
    if user.totp_item.verify(otp) is False:
        return False, response.HttpResponseForbidden(reason="Bad OTP")
    return True, None


def get_otp_from_body(body: HttpRequest.body):
    try:
        otp = json.loads(body).get("otp_code")
    except (json.JSONDecodeError, KeyError):
        return None
    return otp
