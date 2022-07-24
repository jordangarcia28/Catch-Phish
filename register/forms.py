import django

from django import forms
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm, UsernameField
from django.contrib.auth.models import User




class RegisterForm(UserCreationForm):
   
    # email = forms.EmailField()
    email = forms.EmailField(widget=forms.TextInput(attrs={ "id": "text-fb59", "name": "text-2", "class":"u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-1"}))
    username = forms.CharField(widget=forms.TextInput(attrs={ "id": "text-fb83", "name": "text", "class":"u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-2"}))
    # # username = forms.CharField(widget=forms.TextInput(attrs={ "id": "text-fb83", "name": "text", "class":""}))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs={ "id": "text-9218", "name": "text-1", "class":"u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-3"}), label='Password')
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={ "id": "text-e0ee", "name": "text-3", "class":"u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-4"}), label='Password Confirmation')
    # password2 = forms.PasswordInput()
    class Meta:
        model = User
        fields = ["email", "username", "password1", "password2"]

class UpdateUserForm(forms.ModelForm):
    username = forms.CharField(max_length=100,
                               required=True,
                               widget=forms.TextInput(attrs={"id": "name-56ad", "name": "Username", "class":"u-border-1 u-border-grey-30 u-input u-input-rectangle u-white"}))
    # username = forms.CharField(widget=forms.TextInput(attrs={ "id": "text-fb83", "name": "text", "class":"u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-2"}))
    
    email = forms.EmailField(required=True,
                             widget=forms.TextInput(attrs={"id": "email-56ad", "name": "email", "class":"u-border-1 u-border-grey-30 u-input u-input-rectangle u-white"}))

    class Meta:
        model = User
        fields = ['username', 'email']

class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={ "id": "text-fb83", "name": "text", "class":"u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-1"}))
    password = forms.CharField(max_length=63, widget=forms.PasswordInput(attrs={ "id": "text-fb83", "name": "text", "class":"u-border-2 u-border-grey-30 u-custom-font u-input u-input-rectangle u-radius-5 u-white u-input-2"}))

   
