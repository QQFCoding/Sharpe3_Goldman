"""Offline RS256 verification. Keys and maximum permissions are operator-owned."""
import json

import jwt


class JwtVerifier:
    def __init__(self, path, issuer, audience, identities):
        self.issuer, self.audience, self.identities = issuer, audience, identities
        self.keys = {}
        for item in json.loads(path.read_text(encoding="utf-8"))["keys"]:
            if item.get("kty") != "RSA" or item.get("alg") != "RS256" or "d" in item:
                raise ValueError("JWKS requires public RS256 keys")
            if item["kid"] in self.keys:
                raise ValueError("Duplicate JWKS kid")
            self.keys[item["kid"]] = jwt.PyJWK.from_dict(item).key

    def authenticate(self, token):
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != "RS256" or any(k in header for k in ("jku", "x5u", "jwk")):
                return None
            claims = jwt.decode(token, self.keys[header["kid"]], algorithms=["RS256"],
                issuer=self.issuer, audience=self.audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "tenant", "agent_id", "scopes"]})
            if not isinstance(claims["scopes"], list) or not all(isinstance(s, str) for s in claims["scopes"]):
                return None
            candidates = [p for p in self.identities.values() if p.subject == claims["sub"]
                and p.tenant_id == claims["tenant"] and p.agent_id == claims["agent_id"]]
            if len(candidates) != 1 or not set(claims["scopes"]) <= set(candidates[0].scopes):
                return None
            return candidates[0].model_copy(update={"scopes": claims["scopes"], "authentication_method": "jwt"}, deep=True)
        except (jwt.PyJWTError, KeyError, ValueError, TypeError):
            return None
