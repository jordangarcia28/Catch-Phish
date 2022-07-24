# Generated by Django 3.2.5 on 2022-07-06 19:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('predict', '0009_whoismodel'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='historymodel',
            name='whois_detail',
        ),
        migrations.AddField(
            model_name='historymodel',
            name='whois_domain',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='historymodel',
            name='whois_registrar',
            field=models.CharField(max_length=200, null=True),
        ),
        migrations.DeleteModel(
            name='WhoisModel',
        ),
    ]
