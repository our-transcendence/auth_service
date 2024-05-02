"""
URL configuration for auth project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls')
"""
# Django imports
from django.contrib import admin
from django.urls import path

# Local application/library specific imports
from login import register_login, otp, utils


urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', register_login.login_endpoint),
    path('register/', register_login.register_endpoint),
    path('refresh/', register_login.refresh_auth_token),
    path('public_key/', utils.pubkey_retrieval),
    path('enable_totp/', otp.set_totp),
    path('otp/', otp.otp_submit)
]
