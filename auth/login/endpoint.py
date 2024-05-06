
@csrf_exempt
@require_GET
def login_42_page(request: HttpRequest):
    return response.HttpResponse(settings.LOGIN_42_PAGE_URL)

@csrf_exempt
@require_GET
def token_42(request: HttpRequest):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponseBadRequest(reason="JSON Decode Error")

    expected_keys = {"code"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponseBadRequest(reason="Bad Keys")
    code = data["code"]

    post_data = {
        "grant_type": "authorization_code",
        "client_id": settings.API_42_UID,
        "client_secret": settings.API_42_SECRET,
        "redirect_uri": settings.API_42_REDIRECT_URI,
        "code": code,
    }
    try:
        oauth_response = requests.post("https://api.intra.42.fr/oauth/token", data=post_data)
    except requests.exceptions.ConnectionError:
        return response.HttpResponse(status=500, reason="Cant connect to 42 api")
    if oauth_response.status_code != 200:
        return response.HttpResponse(status=oauth_response.status_code, reason=f"Error: {oauth_response.status_code}, {oauth_response.text}")
    access_token = oauth_response.json().get("access_token")
    response_content = {"access_token" : access_token}
    return response.JsonResponse(response_content)

@csrf_exempt
@require_GET
def login_42_endpoint(request: HttpRequest):
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponseBadRequest(reason="JSON Decode Error")

    expected_keys = {"access_token"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponseBadRequest(reason=f"Bad Keys {data.keys()}, expecting {expected_keys}")
    access_token = data["access_token"]

    login_42, httpError = get_42_login(access_token)
    if login_42 is None:
        return httpError

    # search if login exists in database
    if not User.objects.filter(login_42=login_42).exists():
        return response.HttpResponseBadRequest(reason="There is no account associated with this 42 account")
        # then just login
    user = User.objects.filter(login_42=login_42)[0]
    return return_refresh_token(user)

@csrf_exempt
@require_POST
def link_42(request: HttpRequest):
    # check access_token
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return response.HttpResponseBadRequest(reason="JSON Decode Error")

    expected_keys = {"access_token"}
    if set(data.keys()) != expected_keys:
        return response.HttpResponseBadRequest(reason=f"Bad Keys {data.keys()}, expecting {expected_keys}")
    access_token = data["access_token"]

    # check auth_token for our_transcendence
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


    login_42, httpError = get_42_login(access_token)
    if login_42 is None:
        return httpError

    user.login_42 = login_42
    return response.HttpResponseOK()

def get_42_login(access_token):
    # try request to api with the token
    try:
        profile_request_header = {"Authorization": f"Bearer {access_token}"}
        profile_response = requests.get("https://api.intra.42.fr/v2/me", headers=profile_request_header)
    except requests.exceptions.RequestException:
        return None, response.HttpResponse(status=500, reason="Cant connect to 42 api")

    if profile_response.status_code != 200:
        return None, response.HttpResponse(status=profile_response.status_code, reason=f"Error: {profile_response.status_code}")
    # get the login
    try:
        data = json.loads(profile_response.text)
    except json.JSONDecodeError:
        return None, response.HttpResponseBadRequest(reason="JSON Decode Error")
    login_42 = data["login"]
    return login_42, None
