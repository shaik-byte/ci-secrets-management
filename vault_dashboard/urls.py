from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name="vault_dashboard"),
    path('add-environment/', views.add_environment, name="add_environment"),
    path('add-folder/<int:env_id>/', views.add_folder, name="add_folder"),
    path('add-secret/<int:folder_id>/', views.add_secret, name="add_secret"),
    path('reveal-secret/<int:secret_id>/', views.reveal_secret, name="reveal_secret"),
    path('toggle-secret-access/<int:secret_id>/', views.toggle_secret_access, name="toggle_secret_access"),
    path('delete-environment/<int:env_id>/', views.delete_environment, name="delete_environment"),
    path('delete-folder/<int:folder_id>/', views.delete_folder, name="delete_folder"),
    path('delete-secret/<int:secret_id>/', views.delete_secret, name="delete_secret"),
]
