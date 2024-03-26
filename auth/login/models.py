from django.db import models
from django.core.validators import MinLengthValidator


# Create your models here.
class User(models.Model):
    login = models.CharField(max_length=15)
    password = models.CharField(
        max_length=25,
        validators=[MinLengthValidator(5, "Must contains at least 5 char")]
    )
