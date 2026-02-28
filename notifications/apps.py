# from django.apps import AppConfig


# class NotificationsConfig(AppConfig):
#     name = 'notifications'
from django.apps import AppConfig

class NotificationsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'notifications'

    def ready(self):
        from .scheduler import start_scheduler
        start_scheduler()