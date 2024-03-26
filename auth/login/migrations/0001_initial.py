# Generated by Django 4.2.11 on 2024-03-25 15:42

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='user',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('login', models.CharField(max_length=15)),
                ('password', models.CharField(max_length=25, validators=[django.core.validators.MinLengthValidator(5, 'Must contains at least 5 char')])),
            ],
        ),
    ]