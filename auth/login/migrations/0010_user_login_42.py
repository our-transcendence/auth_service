# Generated by Django 5.0.4 on 2024-04-28 19:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('login', '0008_remove_user_displayname_remove_user_gunfightelo_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='login_42',
            field=models.CharField(blank=True, max_length=15, null=True, unique=True),
        ),
    ]
