from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name="vault_dashboard"),
    path('add-environment/', views.add_environment, name="add_environment"),
    path('add-folder/<int:env_id>/', views.add_folder, name="add_folder"),
    path('add-secret/<int:folder_id>/', views.add_secret, name="add_secret"),
    path('reveal-secret/<int:secret_id>/', views.reveal_secret, name="reveal_secret"),
    path('toggle-secret-access/<int:secret_id>/', views.toggle_secret_access, name="toggle_secret_access"),
    path('settings/save-secret-policy/', views.save_secret_policy, name="save_secret_policy"),
    path('policy-engine/save-ui/', views.save_access_policy_ui, name="save_access_policy_ui"),
    path('policy-engine/save-document/', views.save_access_policy_document, name="save_access_policy_document"),
    path('policy-engine/delete/<int:policy_id>/', views.delete_access_policy, name="delete_access_policy"),
    path('policy-engine/groups/create/', views.create_policy_group, name="create_policy_group"),
    path('policy-engine/groups/add-user/', views.add_user_to_policy_group, name="add_user_to_policy_group"),
    path('policy-engine/groups/remove-user/', views.remove_user_from_policy_group, name="remove_user_from_policy_group"),
    path('policy-engine/groups/attach-policy/', views.attach_policy_to_group, name="attach_policy_to_group"),
    path('policy-engine/groups/detach-policy/', views.detach_policy_from_group, name="detach_policy_from_group"),
    path('policy-engine/groups/save-document/', views.save_policy_groups_document, name="save_policy_groups_document"),
    path('delete-environment/<int:env_id>/', views.delete_environment, name="delete_environment"),
    path('delete-folder/<int:folder_id>/', views.delete_folder, name="delete_folder"),
    path('delete-secret/<int:secret_id>/', views.delete_secret, name="delete_secret"),
]
