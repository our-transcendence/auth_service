# Generated by Django 5.0.4 on 2024-04-22 15:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0003_alter_user_password_alter_user_picture'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='login_attempt',
            field=models.DateField(default=None),
        ),
        migrations.AddField(
            model_name='user',
            name='totp_enabled',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='user',
            name='totp_key',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
