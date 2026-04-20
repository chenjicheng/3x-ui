#!/usr/bin/env python3
"""
Minimal OIDC Authorization Code + PKCE mock server.
Auto-grants all auth requests without user interaction.
For CI testing only — never use in production.
"""
import hashlib
import json
import time
import secrets
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

PORT = 9998
BASE_URL = f"http://localhost:{PORT}"
TEST_SUB = "ci-test-user-001"
TEST_EMAIL = "ci@test.local"

# Generate RSA-2048 key pair once on startup
_priv = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_priv_pem = _priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
_pub_nums = _priv.public_key().public_numbers()


def _b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


_jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "kid": "ci-key-1",
        "alg": "RS256",
        "n": _b64url(_pub_nums.n),
        "e": _b64url(_pub_nums.e),
    }]
}

# code -> {redirect_uri, nonce}
_codes: dict = {}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _body_params(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        return parse_qs(self.rfile.read(n).decode(), keep_blank_values=True)

    def do_GET(self):
        p = urlparse(self.path)
        qs = parse_qs(p.query, keep_blank_values=True)

        if p.path == "/.well-known/openid-configuration":
            self._json({
                "issuer": BASE_URL,
                "authorization_endpoint": f"{BASE_URL}/auth",
                "token_endpoint": f"{BASE_URL}/token",
                "jwks_uri": f"{BASE_URL}/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
                "scopes_supported": ["openid", "profile", "email"],
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post", "client_secret_basic",
                ],
                "claims_supported": ["sub", "email", "email_verified"],
                "code_challenge_methods_supported": ["S256"],
            })

        elif p.path == "/auth":
            redirect_uri = (qs.get("redirect_uri") or [""])[0]
            state = (qs.get("state") or [""])[0]
            nonce = (qs.get("nonce") or [""])[0]
            code_challenge = (qs.get("code_challenge") or [""])[0]
            code_challenge_method = (qs.get("code_challenge_method") or [""])[0]
            code = secrets.token_urlsafe(32)
            _codes[code] = {
                "redirect_uri": redirect_uri,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            }
            self._redirect(f"{redirect_uri}?code={code}&state={state}")

        elif p.path == "/jwks":
            self._json(_jwks)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        p = urlparse(self.path)
        params = self._body_params()

        if p.path == "/token":
            code = (params.get("code") or [""])[0]
            info = _codes.pop(code, None)
            if not info:
                self._json({"error": "invalid_grant"}, 400)
                return

            # Validate redirect_uri matches the one used in /auth
            redirect_uri = (params.get("redirect_uri") or [""])[0]
            if redirect_uri != info["redirect_uri"]:
                self._json({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, 400)
                return

            # Validate PKCE code_verifier against stored code_challenge (S256 only)
            code_verifier = (params.get("code_verifier") or [""])[0]
            if info.get("code_challenge"):
                if not code_verifier:
                    self._json({"error": "invalid_grant", "error_description": "missing code_verifier"}, 400)
                    return
                if info.get("code_challenge_method", "S256") != "S256":
                    self._json({"error": "invalid_request", "error_description": "unsupported code_challenge_method"}, 400)
                    return
                digest = hashlib.sha256(code_verifier.encode()).digest()
                computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                if computed != info["code_challenge"]:
                    self._json({"error": "invalid_grant", "error_description": "code_verifier mismatch"}, 400)
                    return

            client_id = (params.get("client_id") or ["3x-ui-e2e"])[0]
            now = int(time.time())
            tok = jwt.encode(
                {
                    "iss": BASE_URL,
                    "sub": TEST_SUB,
                    "aud": client_id,
                    "exp": now + 3600,
                    "iat": now,
                    "nonce": info["nonce"],
                    "email": TEST_EMAIL,
                    "email_verified": True,
                },
                _priv_pem,
                algorithm="RS256",
                headers={"kid": "ci-key-1"},
            )
            if isinstance(tok, bytes):
                tok = tok.decode()

            self._json({
                "access_token": secrets.token_urlsafe(32),
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": tok,
            })

        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"Mock OIDC server running at {BASE_URL}", flush=True)
    server.serve_forever()
