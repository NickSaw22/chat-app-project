# Generated by Django 2.0 on 2021-05-28 14:18

from django.db import migrations
import fernet_fields.fields


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0006_auto_20210528_1916'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='message',
            field=fernet_fields.fields.EncryptedTextField(),
        ),
    ]
