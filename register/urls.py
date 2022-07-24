from django.urls import path
from register import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('profile/', views.profile, name='user-profile'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
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