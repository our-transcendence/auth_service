# Generated by Django 5.0.4 on 2024-04-24 07:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0006_alter_user_login_attempt'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='login_attempt',
            field=models.DateTimeField(blank=True, default=None, null=True),
        ),
    ]