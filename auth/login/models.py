from datetime import datetime, timedelta

from django.db import models
from django.core.validators import MinLengthValidator
from django.conf import settings

from crypto import encoder

# Create your models here.
class User(models.Model):
    id = models.BigAutoField(primary_key=True)
    login = models.CharField(max_length=15, unique=True)
    password = models.CharField(
        max_length=25,
        validators=[MinLengthValidator(5, "Must contains at least 5 char")]
    )
    displayName = models.CharField(
        max_length=25,
        validators=[MinLengthValidator(5, "Must contains at least 5 char")],
        null=True
    )
    pongElo = models.PositiveIntegerField(default=200)
    gunFightElo = models.PositiveIntegerField(default=200)
    picture = models.CharField(max_length=25, null=True)
    jwt_emitted = models.IntegerField(default=0)

    def generate_refresh_token(self):
        expdate = datetime.now() + timedelta(days=7)
        payload = {
            "sub": self.login,
            "id": self.jwt_emitted,
            "exp": expdate
        }
        return encoder.encode(payload, "refresh")
