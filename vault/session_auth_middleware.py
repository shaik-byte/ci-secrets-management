from django.http import JsonResponse
from django.shortcuts import redirect


class SessionAuthRequiredMiddleware:
    """
    Enforces session-backed authentication for protected app areas.

    Session validation point:
    - For protected URL prefixes, if `request.user` is not authenticated
      (resolved from Django session + auth middleware), redirect to login.
    """

    PROTECTED_PREFIXES = ("/secrets/", "/notifications/", "/audit-logs/")
    EXEMPT_PREFIXES = (
        "/login/",
        "/logout/",
        "/initialize/",
        "/unseal/",
        "/begin-auth/",
        "/finish-auth/",
        "/begin-registration/",
        "/finish-registration/",
        "/secrets/policy-engine/machine/jwt/login/",
        "/secrets/policy-engine/machine/approle/login/",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        if path.startswith(self.PROTECTED_PREFIXES) and not path.startswith(self.EXEMPT_PREFIXES):
            auth_header = (request.headers.get("Authorization") or "").strip().lower()
            has_bearer_token = auth_header.startswith("bearer ")
            accepts_json = "application/json" in (request.headers.get("Accept") or "").lower()
            is_api_style = has_bearer_token or accepts_json or path.startswith("/secrets/cli/") or path.startswith("/secrets/list/")

            if not request.user.is_authenticated and not has_bearer_token:
                if is_api_style:
                    return JsonResponse({"ok": False, "error": "Authentication required."}, status=401)
                # Redirect unauthenticated users to login (with `next`) for protected pages.
                return redirect(f"/login/?next={path}")

        return self.get_response(request)
