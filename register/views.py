from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import PasswordChangeView
from django.contrib.messages.views import SuccessMessageMixin
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib import messages, auth
from django.urls import reverse_lazy
from .forms import RegisterForm, UpdateUserForm, LoginForm


# Create your views here.
def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')
    else:
        form = RegisterForm()
        return render(request, "register/register.html", {"form":form})

    return render(request, "register/register.html", {"form":form})




def login_view(request):
    form = LoginForm()
    message = 'fsdf'
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('/')
            else:
                form = LoginForm(request.POST)
                message = 'Log in failed. Username or password is incorrect.'
                return render(request, 'registration/login.html', {'form': form, 'message':message})
    return render(request, 'registration/login.html', context={'form': form})


@login_required
def logout(request):
    auth.logout(request)
    return HttpResponseRedirect('/')




@login_required
def profile(request):
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)

        if user_form.is_valid():
            user_form.save()
            # messages.success(request, 'Your profile is updated successfully')
            message = 'Your profile is updated successfully.'
            return render(request, 'user/profile.html', {'user_form': user_form, 'message':message})
            # return redirect(to='/profile/')
    else:
        user_form = UpdateUserForm(instance=request.user)


    return render(request, 'user/profile.html', {'user_form': user_form})

class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'user/change_password.html'
    success_message = "Successfully Changed Your Password"
    # success_url = reverse_lazy('users-home')



# def login(request):
#     if request.user.is_authenticated:
#         return redirect('/')
#     if request.method == 'POST':
#         username = request.POST['username']
#         password = request.POST['password']
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             login(request)
#             return redirect('/')
#         else:
#             form = AuthenticationForm(request.POST)
#             return render(request, 'registration/login.html', {'form': form})
#     else:
#         form = AuthenticationForm()
#         return render(request, 'registration/login.html', {'form': form})
