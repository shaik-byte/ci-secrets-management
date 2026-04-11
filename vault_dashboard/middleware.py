import time

class AutoSealMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            request.session["last_activity"] = time.time()

        response = self.get_response(request)
        return response
