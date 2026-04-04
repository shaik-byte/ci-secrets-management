from django.db import connections
from django.shortcuts import redirect
from django.urls import reverse
from django.core.cache import cache


class VaultHardSealMiddleware:
    """When hard sealed, block app routes and close DB connections for the request."""

    ALLOWED_PREFIXES = (
        "/initialize/",
        "/unseal/",
        "/begin-auth/",
        "/finish-auth/",
        "/begin-registration/",
        "/finish-registration/",
        "/login/",
        "/logout/",
        "/admin/",
        "/static/",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        hard_sealed = bool(cache.get("vault_hard_sealed", False))

        if hard_sealed and not request.path.startswith(self.ALLOWED_PREFIXES):
            connections.close_all()
            return redirect("unseal")

        return self.get_response(request)
