from django.shortcuts import render
from django.contrib import messages
from login.models import User

import json


# Create your views here.
def login(request):
    if request.method == 'POST':
        string = f'POST method call'
        data = json.loads(request.body)
        username = data["username"]
        password = data["password"]
        try:
            loged = User.objects.get(login=username)
        except User.DoesNotExist:
            string = f'User {username} does not exist'
            return render(request,
                          'login/login.html',
                          {"string": string})
        if loged.password == password:
            string = f'User {loged.login} authentified'
        else:
            string = f'Wrong password for user {loged.login}'
    else:
        string = f'GET method call'
    return render(request,
                  'login/login.html',
                  {"string": string})

def register(request):
    if request.method == "POST":
        string = f'POST register method call'
        data = json.loads(request.body)
    else:
        string = 'GET register method call'
    return render(request,
                  'login/login.html',
                  {"string": string})