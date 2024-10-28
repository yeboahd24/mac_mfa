"""
URL configuration for mac project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, re_path
from user.views import LoginView
from user.device import LoginView
from user.device_compliance import LoginView
from user.mfa import MFACreateView, MFAVerifyView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", LoginView.as_view(), name="login"),
    path("device/login/", LoginView.as_view(), name="device_login"),
    path(
        "device/login_compliance/", LoginView.as_view(), name="device_login_compliance"
    ),
    path("mfa/create/", MFACreateView.as_view(), name="mfa_create"),
    re_path(
        r"^totp/login/(?P<token>[0-9]{6})/$", MFAVerifyView.as_view(), name="mfa_verify"
    ),
]
