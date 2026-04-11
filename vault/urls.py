from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('initialize/', views.initialize_vault, name='initialize'),
    path('unseal/', views.unseal_vault, name='unseal'),
    path('login/', views.login_view, name='login'),
    path('login/oauth/<str:provider>/start/', views.oauth_login_start, name='oauth_login_start'),
    path('login/oauth/<str:provider>/callback/', views.oauth_login_callback, name='oauth_login_callback'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('seal/', views.seal_vault, name='seal'),
]
