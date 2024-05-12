# Standard library imports
from datetime import timedelta
import base64
import binascii
import json

# Django imports
from django.contrib.auth import hashers
from django.core import exceptions
from django.db import OperationalError, IntegrityError, DataError
from django.http import response, HttpRequest, Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
# Third-party imports


# Local application/library specific imports
from login.models import User
from ..utils import send_new_user, get_user_from_jwt
from ..cookie import return_auth_cookie, return_refresh_token

import ourJWT.OUR_exception

NO_USER = 404, "No user found with given ID"

@csrf_exempt
def delete_endpoint(request: HttpRequest, **kwargs):
   print("delete called", flush=True)
   return response.HttpResponse()
