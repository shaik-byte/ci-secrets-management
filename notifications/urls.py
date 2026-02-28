from django.urls import path
from . import views

urlpatterns = [
    path('', views.notification_dashboard, name='notifications'),
    path('save/', views.save_notification_config, name='save_notification_config'),
]