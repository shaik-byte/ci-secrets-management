from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('.well-known/jwks.json', views.jwks_view, name='jwks'),
    path('initialize/', views.initialize_vault, name='initialize'),
    path('unseal/', views.unseal_vault, name='unseal'),
    path('login/', views.login_view, name='login'),
    path('login/root-token/', views.root_token_login_view, name='root_token_login'),
    path('login/cli/', views.cli_login, name='cli_login'),
    path('root/users/create/', views.root_create_user, name='root_create_user'),
    path('logout/', views.logout_view, name='logout'),
    path('logout/cli/', views.cli_logout, name='cli_logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('seal/', views.seal_vault, name='seal'),
]
