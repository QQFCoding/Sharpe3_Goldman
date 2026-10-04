"""Generate a local demo key/JWKS; private key stays ignored. Never runs at startup."""
import argparse
import json
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    path = ROOT / "demo/jwt-private.pem"
    if args.generate and not path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())) | {"kid": "local-demo", "alg": "RS256", "use": "sig"}
        (ROOT / "config/demo-jwks.json").write_text(json.dumps({"keys": [jwk]}, indent=2) + "\n")
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    print(jwt.encode({"iss": "http://aicl.local/issuer", "aud": "ai-control-layer", "sub": "alice",
        "tenant": "tenant-a", "agent_id": "demo-agent", "scopes": ["repo:read", "files:read"],
        "iat": int(time.time()), "exp": int(time.time()) + 300}, key, algorithm="RS256", headers={"kid": "local-demo"}))


if __name__ == "__main__":
    main()
