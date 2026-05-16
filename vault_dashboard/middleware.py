import time
from ipaddress import ip_address, ip_network

from django.conf import settings
from django.core.cache import cache
from django.http import HttpResponseForbidden


class AutoSealMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            request.session["last_activity"] = time.time()

        response = self.get_response(request)
        return response


class TrustedCIDRAllowlistMiddleware:
    """
    Blocks application access when active TrustedCIDR rows exist and the
    request source IP does not belong to any active CIDR range.

    By default, the middleware uses REMOTE_ADDR only. Deployments behind a
    trusted reverse proxy can opt in to a proxy header by setting:
      TRUSTED_CIDR_TRUST_PROXY_HEADERS = True
      TRUSTED_CIDR_IP_HEADER = "HTTP_X_FORWARDED_FOR"
    """

    CACHE_KEY = "trusted_cidr_allowlist:active_ranges:v1"
    CACHE_TTL_SECONDS = 30

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        client_ip = self._get_client_ip(request)
        if not self._is_request_allowed(client_ip):
            return HttpResponseForbidden("Access denied: your IP address is not in the trusted CIDR allowlist.")
        return self.get_response(request)

    @classmethod
    def _get_client_ip(cls, request):
        header_name = getattr(settings, "TRUSTED_CIDR_IP_HEADER", "REMOTE_ADDR")
        trust_proxy_headers = getattr(settings, "TRUSTED_CIDR_TRUST_PROXY_HEADERS", False)

        if trust_proxy_headers and header_name != "REMOTE_ADDR":
            header_value = request.META.get(header_name, "")
            if header_value:
                return header_value.split(",", 1)[0].strip()

        return request.META.get("REMOTE_ADDR", "")

    @classmethod
    def _active_cidr_ranges(cls):
        cidr_ranges = cache.get(cls.CACHE_KEY)
        if cidr_ranges is not None:
            return cidr_ranges

        from .models import TrustedCIDR

        cidr_ranges = list(TrustedCIDR.objects.filter(is_active=True).values_list("cidr_range", flat=True))
        cache.set(cls.CACHE_KEY, cidr_ranges, cls.CACHE_TTL_SECONDS)
        return cidr_ranges

    @classmethod
    def _is_request_allowed(cls, client_ip):
        cidr_ranges = cls._active_cidr_ranges()
        if not cidr_ranges:
            return True

        try:
            parsed_ip = ip_address(client_ip)
        except ValueError:
            return False

        for cidr_range in cidr_ranges:
            try:
                if parsed_ip in ip_network(cidr_range, strict=False):
                    return True
            except ValueError:
                continue
        return False
