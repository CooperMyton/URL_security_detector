from django.urls import path
from . import views

urlpatterns = [
    path('', views.mainQueryPage, name='mainPage'),
    path('mainPage/', views.mainQueryPage, name='mainPage'),
]