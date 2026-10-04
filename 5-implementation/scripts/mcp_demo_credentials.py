"""Provision separate demo server/capability JWTs; write ignored file, never print bearer tokens."""
import json
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]


def main():
    key_path = ROOT / "demo/jwt-private.pem"
    if not key_path.is_file():
        from cryptography.hazmat.primitives.asymmetric import rsa
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": "local-demo", "alg": "RS256", "use": "sig"}
        (ROOT / "config/demo-jwks.json").write_text(json.dumps({"keys": [public]}, indent=2) + "\n")
    key = serialization.load_pem_private_key(key_path.read_bytes(), None)
    records = []
    for server in json.loads((ROOT / "config/mcp-servers.json").read_text()):
        capabilities = [["mcp:discover"], ["repo:read"], ["network:read"]] if server["id"] == "untrusted-external" else [["mcp:discover"], ["repo:read"], ["repo:write"], ["files:read"]]
        for scopes in capabilities:
            token = jwt.encode({"iss": server["issuer"], "aud": server["resource"], "sub": "gateway-demo",
                "scope": " ".join(scopes), "iat": int(time.time()), "exp": int(time.time()) + 86400},
                key, algorithm="RS256", headers={"kid": "local-demo"})
            records.append({"server_id": server["id"], "issuer": server["issuer"], "resource": server["resource"],
                "scopes": scopes, "access_token": token})
    (ROOT / "config/mcp-credentials.json").write_text(json.dumps(records, indent=2) + "\n")
    print(f"Provisioned {len(records)} local demo capability credentials (24-hour expiry).")


if __name__ == "__main__":
    main()
