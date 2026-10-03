import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.auth import Authenticator
from app.core.jwt_auth import JwtVerifier


@pytest.mark.parametrize("failure", [None, "expired", "issuer", "audience", "signature", "escalation", "tenant", "agent", "algorithm", "missing_exp"])
def test_local_rs256_claim_verification(tmp_path, failure):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": "demo", "alg": "RS256"}
    path = tmp_path / "jwks.json"
    path.write_text(json.dumps({"keys": [jwk]}))
    auth = Authenticator(True, None)
    verifier = JwtVerifier(path, "local-issuer", "aicl", auth.records)
    claims = {"sub": "alice", "tenant": "tenant-a", "agent_id": "demo-agent", "scopes": ["repo:read"],
        "iss": "local-issuer", "aud": "aicl", "iat": int(time.time()), "exp": int(time.time()) + 300,
        "roles": ["forged-admin"]}
    if failure == "expired":
        claims["exp"] = int(time.time()) - 1
    elif failure in {"issuer", "audience", "tenant", "agent"}:
        claims[{"issuer": "iss", "audience": "aud", "tenant": "tenant", "agent": "agent_id"}[failure]] = "wrong"
    elif failure == "escalation":
        claims["scopes"] = ["repo:admin"]
    elif failure == "missing_exp":
        del claims["exp"]
    signing = rsa.generate_private_key(public_exponent=65537, key_size=2048) if failure == "signature" else key
    token = jwt.encode(claims, "synthetic-key-for-hmac-test-32-characters" if failure == "algorithm" else signing,
        algorithm="HS256" if failure == "algorithm" else "RS256", headers={"kid": "demo"})
    principal = verifier.authenticate(token)
    if failure:
        assert principal is None
    else:
        assert principal.scopes == ["repo:read"]
        assert not principal.roles
