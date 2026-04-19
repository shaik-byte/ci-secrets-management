from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('initialize/', views.initialize_vault, name='initialize'),
    path('unseal/', views.unseal_vault, name='unseal'),
    path('login/', views.login_view, name='login'),
    path('login/cli/', views.cli_login, name='cli_login'),
    path('logout/', views.logout_view, name='logout'),
    path('logout/cli/', views.cli_logout, name='cli_logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('seal/', views.seal_vault, name='seal'),
]
