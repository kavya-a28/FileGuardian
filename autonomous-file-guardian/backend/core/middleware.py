from django.http import JsonResponse
from core.vault import vault

class VaultMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # List of endpoints allowed even if vault is locked
        allowed_paths = [
            '/api/vault/status/',
            '/api/vault/unlock/',
            '/api/vault/setup/',
            '/api/settings/', # Allow checking settings
        ]

        # 1. Check if path is in allowed list
        if request.path in allowed_paths:
            return self.get_response(request)

        # 2. If Vault is LOCKED, block everything else
        if not vault.is_active():
            return JsonResponse({
                'error': 'Vault is Locked', 
                'is_locked': True,
                'detail': 'Please enter Master Key to unlock database.'
            }, status=423) # 423 Locked

        # 3. If Unlocked, proceed normally
        return self.get_response(request)