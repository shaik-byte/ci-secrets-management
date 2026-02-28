import time
from django.shortcuts import redirect
from vault.models import VaultConfig
from django.contrib.auth import logout

TIMEOUT = 600  # 10 minutes

class AutoSealMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        if request.user.is_authenticated:

            now = time.time()
            last_activity = request.session.get("last_activity", now)

            if now - last_activity > TIMEOUT:
                vault = VaultConfig.objects.first()
                if vault:
                    vault.is_sealed = True
                    vault.save()

                logout(request)
                return redirect("login")

            request.session["last_activity"] = now

        response = self.get_response(request)
        return response