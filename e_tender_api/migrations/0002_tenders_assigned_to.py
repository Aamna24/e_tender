# Generated by Django 3.1.2 on 2021-05-26 18:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('e_tender_api', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='tenders',
            name='assigned_to',
            field=models.CharField(default='', max_length=255),
        ),
    ]
