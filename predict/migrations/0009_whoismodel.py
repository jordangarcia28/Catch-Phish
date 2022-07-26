# Generated by Django 3.2.5 on 2022-07-06 19:11

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('predict', '0008_alter_historymodel_screenshot'),
    ]

    operations = [
        migrations.CreateModel(
            name='WhoisModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('whois_domain', models.CharField(max_length=200)),
                ('whois_registrar', models.CharField(max_length=200)),
                ('whois_detail', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='predict.historymodel')),
            ],
        ),
    ]
