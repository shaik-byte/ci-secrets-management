def session_state(request):
    """
    Exposes minimal session/auth state for frontend rendering.
    No sensitive data is stored in or exposed from cookies.
    """
    if not request.user.is_authenticated:
        return {"session_state": {"is_authenticated": False}}

    return {
        "session_state": {
            "is_authenticated": True,
            "session_key": request.session.session_key,
            "user": {
                "id": request.user.id,
                "username": request.user.username,
                "is_superuser": request.user.is_superuser,
            },
        }
    }
