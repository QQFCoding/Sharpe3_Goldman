"""Operator-provisioned issuer/resource/scope-bound credentials. Never forward client tokens."""
import json

import jwt


def validate_authorization_issuer(expected, received, advertised=True):
    if (advertised and received is None) or (received is not None and received != expected):
        raise ValueError("MCP_ISSUER_MISMATCH")


class ServerCredentials:
    def __init__(self, jwks_path, credentials_path=None):
        self.keys = {key["kid"]: jwt.PyJWK.from_dict(key).key
            for key in json.loads(jwks_path.read_text(encoding="utf-8"))["keys"]
            if key.get("alg") == "RS256" and "d" not in key}
        self.records = json.loads(credentials_path.read_text(encoding="utf-8")) if credentials_path and credentials_path.is_file() else []

    def verify(self, token, issuer, audience, required):
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or any(k in header for k in ["jku", "x5u", "jwk"]):
            raise ValueError("MCP_CREDENTIAL_INVALID")
        claims = jwt.decode(token, self.keys[header["kid"]], algorithms=["RS256"], issuer=issuer,
            audience=audience, options={"require": ["exp", "iat", "iss", "aud", "sub", "scope"]})
        if claims["iss"] != issuer or claims["aud"] != audience:
            raise ValueError("MCP_CREDENTIAL_RESOURCE_MISMATCH")
        scopes = claims["scope"].split() if isinstance(claims["scope"], str) else []
        if not set(required) <= set(scopes):
            raise PermissionError("MCP_SCOPE_STEP_UP_REQUIRED")
        return claims

    def for_server(self, server, scopes):
        candidates = sorted([r for r in self.records if r["server_id"] == server["id"]
            and r["issuer"] == server["issuer"] and r["resource"] == server["resource"]
            and set(scopes) <= set(r["scopes"])], key=lambda r: len(r["scopes"]))
        if not candidates:
            raise PermissionError("MCP_SCOPE_STEP_UP_REQUIRED")
        token = candidates[0]["access_token"]
        self.verify(token, server["issuer"], server["resource"], scopes)
        return token
