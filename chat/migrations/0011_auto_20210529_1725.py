# Generated by Django 2.0 on 2021-05-29 11:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0010_auto_20210529_1148'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='message',
            field=models.BinaryField(),
        ),
    ]
