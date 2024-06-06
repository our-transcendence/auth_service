# docker run -e POSTGRES_PASSWORD=PASSWORD -e POSTGRES_USER=USER -e POSTGRES_DB=DB -p 5432:5432 postgres

"""
Django settings for auth project.

Generated by 'django-admin startproject' using Django 4.2.11.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/

"""
# Standard library imports
import os
import re
import urllib

import urllib3
from pathlib import Path

# Django imports

# Third-party imports

# Local application/library specific imports
from ourJWT import OUR_class, OUR_exception

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

APPEND_SLASH = False

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-bha_z48$lrtojju%5*y5y399k@f%c5!dnu80pbm7u)ccg$l_4y'

CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SECURE = True

urllib3.disable_warnings()  # TODO Remove in prod

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = [
    '82.64.223.220',
    '127.0.0.1',
    'localhost',
    'auth-nginx',
    'user-nginx',
    'chat-nginx',
    'history-nginx',
    'stats-nginx',
    'our-transcendence.games',
    os.getenv("HOST", "127.0.0.1"),
]

CORS_ALLOW_CREDENTIALS = True

CORS_ALLOWED_ORIGINS = [
    "http://localhost",
    "https://localhost",
    "https://127.0.0.1:4443",
    "https://localhost:4443",
    'https://our-transcendence.games',
    f"https://{os.getenv('HOST', '127.0.0.1')}:4443"
]

CORS_ORIGIN_REGEX_WHITELIST = [
    r"^https://127\.0\.0\.1:\d+$",
    r"^https://localhost:\d+$",
]

CORS_ALLOW_ALL_ORIGINS = DEBUG

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'login',
    'corsheaders',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'auth.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'auth.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get("POSTGRES_DB", "DB"),
        'HOST': "postgres",
        "USER": os.environ.get("POSTGRES_USER", "USER"),
        "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "PASSWORD"),
        "PORT": "5432",
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# En production virer le default
try:
    API_42_SECRET =os.environ["API_42_SECRET"]
    API_42_UID = os.environ["API_42_UID"]
    NOT_ENC_HOST = os.environ["HOST"]
except KeyError as e:
    print("At least one of 42_SECRET, 42_UID or HOST is not defined")
    exit(1)

ENC_HOST = urllib.parse.quote("https://" + NOT_ENC_HOST + ":4443/intra/")
print(ENC_HOST)
LOGIN_42_PAGE_URL = f"https://api.intra.42.fr/oauth/authorize?client_id={API_42_UID}&redirect_uri={ENC_HOST}&response_type=code"

API_42_REDIRECT_URI = os.getenv("API_42_REDIRECT_URI", default="https://127.0.0.1:4443")

USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "https://user-nginx:4646")
STATS_SERVICE_URL = os.getenv("STATS_SERVICE_URL", "https://stats-nginx:5151")
