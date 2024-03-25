from django.shortcuts import render
from django.contrib import messages

import json


# Create your views here.
def login(request):
    if request.method == 'POST':
        string = f'POST method call'
        data = json.loads(request.body)
        messages.add_message(request, messages.INFO, f'username : {data["username"]}, password : {data["password"]}')
    else:
        string = f'GET method call'
    return render(request,
                  'login/login.html',
                  {"string": string})
