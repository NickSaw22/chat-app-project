# Generated by Django 2.0 on 2021-05-29 13:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0013_auto_20210529_1905'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='message',
            field=models.CharField(max_length=1200),
        ),
    ]
