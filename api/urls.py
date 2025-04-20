# create urls for the api
from django.urls import path

from . import views

urlpatterns = [
    path("register", views.RegisterView.as_view()),
    path("login", views.LoginView.as_view()),
    path("logout", views.LogoutView.as_view()),
    path("refresh", views.RefreshTokenView.as_view()),
    path("protected", views.ProtectedView.as_view()),
    path("me", views.UserInfoView.as_view()),
    path("update-user-info", views.UpdateUserInfoView.as_view()),
]
