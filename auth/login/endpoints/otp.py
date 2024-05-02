# Standard library imports
from datetime import timedelta
import json


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
    auth_token = request.COOKIES.get("auth_token")
    if auth_token is None:  # pas de token Auth donne, le user n'est pas connecte
        user_id = request.COOKIES.get("otp_user_ID")
        if user_id is None:
            return response.HttpResponseBadRequest()
        try:
            user = get_object_or_404(User, pk=user_id)
        except Http404:
            return response.HttpResponseNotFound("no user found with given ID")
    else:
        try:
            auth = ourJWT.Decoder.decode(auth_token)
        except (ourJWT.BadSubject, ourJWT.RefusedToken, ourJWT.ExpiredToken):
            return response.HttpResponseBadRequest(reason='bad auth token')
        try:
            user = get_user_from_jwt({"token": auth})
        except Http404:
            return response.HttpResponseNotFound("no user found with given ID")

    if user.totp_key is None:
        return response.HttpResponse(status=412, reason="OTP not set up for user")
    if not request.body:
        user.totp_key = None
        user.save()
        return response.HttpResponseBadRequest(reason="empty request")

    user_code = json.loads(request.body).get("otp_code")
    if user_code is None:
        if not user.totp_enabled:
            user.totp_key = None
            user.save()
        return response.HttpResponseBadRequest(reason="No otp in request")
    if (user.login_attempt + timedelta(minutes=1)) < timezone.now():
        if not user.totp_enabled:
            user.totp_key = None
            user.save()
        return response.HttpResponseForbidden(reason="OTP validation timed out")

    user.login_attempt = None
    if not user.totp_item.verify(user_code):
        user.save()
        return response.HttpResponseForbidden(reason="Bad OTP")

    if not user.totp_enabled:
        user.totp_enabled = True
        user.save()
        return response.HttpResponse()
    user.save()
    return return_refresh_token(user=user)
