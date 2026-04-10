from django.shortcuts import redirect


class SessionAuthRequiredMiddleware:
    """
    Enforces session-backed authentication for protected app areas.

    Session validation point:
    - For protected URL prefixes, if `request.user` is not authenticated
      (resolved from Django session + auth middleware), redirect to login.
    """

    PROTECTED_PREFIXES = ("/secrets/", "/notifications/", "/audit-logs/")
    EXEMPT_PREFIXES = ("/login/", "/logout/", "/initialize/", "/unseal/")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        if path.startswith(self.PROTECTED_PREFIXES) and not path.startswith(self.EXEMPT_PREFIXES):
            if not request.user.is_authenticated:
                return redirect(f"/login/?next={path}")

        return self.get_response(request)
