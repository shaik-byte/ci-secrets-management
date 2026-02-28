from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),

    path('initialize/', views.initialize_vault, name='initialize'),
    path('unseal/', views.unseal_vault, name='unseal'),
    

    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('seal/', views.seal_vault, name='seal'),
    path('begin-registration/', views.begin_registration),
    path('finish-registration/', views.finish_registration),

    path('begin-auth/', views.begin_authentication),
    path('finish-auth/', views.finish_authentication),
]
