from django.urls import path
from django.contrib.auth.views import  LoginView
from . import views

urlpatterns = [
    path('createmsg', views.createmsg, name='createmsg'),
    path('showmsgs', views.showmsgs, name='showmsgs'),
    path('readmsg', views.readmsg, name='readmsg'),
    path('delmsg', views.delmsg, name='delmsg'),
    path('unreadmsgs', views.unreadmsgs, name='unreadmsgs'),
    path('login/', LoginView.as_view(template_name='login.html'), name="login"),
    path('login_user', views.login_user, name='login_user'),
    path('logout_user', views.logout_user, name='logout_user')
]