from django.urls import path, reverse_lazy
from register import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('profile/', views.profile, name='user-profile'),
    # path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    # path('change-password/', views.PasswordChangeView.as_view(success_url=reverse_lazy('account:password_change_done')), namespace='change-password'),
    # path('change-password/', views.PasswordChangeView.as_view(), name='change-password'),
    # path('change-password/done/', views.PasswordChangeDoneView.as_view(), name='password_change_done'),
    path('change-password/', views.PasswordsChangeView.as_view(), name='change-password'),
    # path('change-password/done/', views.PasswordChangeDoneView.as_view(), name='password_change_done'),




    # path('login/', views.login, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout, name='logout'),
    # path('login/', views.login, name='login'),
]

# STATIC_URL = '/static/'

# STATICFILES_FINDERS = (
# 'django.contrib.staticfiles.finders.AppDirectoriesFinder',
# 'django.contrib.staticfiles.finders.FileSystemFinder',
# )