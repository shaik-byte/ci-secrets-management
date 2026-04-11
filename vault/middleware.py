from django.core.cache import cache
from django.db import connections
from django.shortcuts import redirect
from vault.models import VaultConfig


class VaultHardSealMiddleware:
    """When hard sealed, block app routes and close DB connections for the request."""

    ALLOWED_PREFIXES = (
        "/initialize/",
        "/unseal/",
        "/login/",
        "/logout/",
        "/admin/",
        "/static/",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if not cache.get("vault_restart_seal_initialized", False):
            vault = VaultConfig.objects.first()
            if vault:
                if not vault.is_sealed:
                    vault.is_sealed = True
                    vault.save(update_fields=["is_sealed"])
                cache.set("vault_hard_sealed", True, None)
            cache.set("vault_restart_seal_initialized", True, None)

        hard_sealed = bool(cache.get("vault_hard_sealed", False))

        if hard_sealed and not request.path.startswith(self.ALLOWED_PREFIXES):
            connections.close_all()
            return redirect("unseal")

        return self.get_response(request)
