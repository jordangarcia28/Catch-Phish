from pyexpat import model
from django.db import models
from django.contrib.auth.models import User
import json


# Create your models here.




class historyModel(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="url_user", null=True)
    url = models.CharField(max_length=250)
    
    is_phishing = models.BooleanField(null=True)
    screenshot = models.ImageField(upload_to='images/', null=True)
    # whois_detail = models.CharField(max_length=250, null=True)
    whois_domain = models.CharField(max_length=200, null=True)
    whois_registrar = models.CharField(max_length=200, null=True)

    whois_ns = models.CharField(max_length=200, null=True)
    whois_name = models.CharField(max_length=200, null=True)
    whois_org = models.CharField(max_length=200, null=True)
    whois_address = models.CharField(max_length=200, null=True)
    whois_city = models.CharField(max_length=200, null=True)
    whois_exp = models.CharField(max_length=200, null=True)
    whois_crt = models.CharField(max_length=200, null=True)
    # def set_foo(self, x):
    #     self.whois_detail = json.dumps(x)

    # def get_foo(self):
    #     return json.loads(self.whois_detail)
    # status = models.CharField(max_length=20, null=True)
    def __str__(self):
        return self.url


class reportModel(models.Model):
    url_report = models.CharField(max_length=250)


    def __str__(self):
        return self.url_report