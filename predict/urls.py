from django.urls import path
from predict import views

urlpatterns = [
    # path('', views.index, name='index'),
    # path('home/', views.index, name='predict'),
    # path('predict/', views.index, name='predict'),
    path('', views.predict, name='predict'),
    # path('', views.report, name='report'),
    # path('result/', views.result, name='result'),
    path("<int:id>", views.result, name="result"),
    # path('', views.PostList.as_view(), name='history'),
    # path('<slug:slug>/', views.PostDetail.as_view(), name='result'),



    path('error/', views.predict, name='error'),
    path('message/', views.predict, name='message'),
    path('history/', views.history, name='history'),
    path('delete/<int:id>', views.delete, name='delete'),
    # path('', PostList.as_view(), name='home'),
    # path('post/<pk>/<slug:slug>', PostDetail.as_view(), name='post'),
]

# STATIC_URL = '/static/'

# STATICFILES_FINDERS = (
# 'django.contrib.staticfiles.finders.AppDirectoriesFinder',
# 'django.contrib.staticfiles.finders.FileSystemFinder',
# )