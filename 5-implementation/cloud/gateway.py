"""Small HTTP-only client. Destination is operator configuration, never browser input."""
import ipaddress
import json
from urllib.parse import urlencode, urlsplit

import httpx


class GatewayError(Exception):
    def __init__(self, message, status=None):
        self.status = status
        super().__init__(message)


def configured_url(value):
    value = str(value).rstrip("/")
    parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
        raise ValueError("Gateway URL must be an origin without credentials, query, path or fragment")
    loopback = parsed.hostname == "localhost"
    try:
        loopback = loopback or ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        pass
    if not parsed.hostname or parsed.scheme not in ("http", "https") or (parsed.scheme == "http" and not loopback):
        raise ValueError("Use HTTPS for remote gateways; HTTP is allowed only on loopback")
    return value


class Gateway:
    def __init__(self, url, token):
        self.url = configured_url(url)
        self.token = token

    def request(self, path, *, method="GET", body=None, params=None, text=False):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("Invalid gateway route")
        try:
            with httpx.Client(timeout=httpx.Timeout(75, connect=5), follow_redirects=False, trust_env=False) as client:
                response = client.request(method, self.url + path, json=body, params=params,
                    headers={"Authorization": "Bearer " + self.token})
        except httpx.HTTPError as exc:
            raise GatewayError("Gateway connection failed. Check its configured address and readiness.") from exc
        if response.status_code == 401 or response.status_code == 403:
            raise GatewayError("Operator authentication rejected. Check the operator token.", response.status_code)
        if not response.is_success:
            # Don't echo arbitrary gateway bodies, which can contain sensitive diagnostics.
            raise GatewayError(f"Gateway returned HTTP {response.status_code}.", response.status_code)
        return response.text if text else response.json()

    def events(self, body):
        """Yield genuine backend stages and enforce a finite, non-redirected SSE stream."""
        try:
            with httpx.Client(timeout=httpx.Timeout(90, connect=5), follow_redirects=False, trust_env=False) as client:
                with client.stream("POST", self.url + "/admin/detection/stream", json=body,
                    headers={"Authorization": "Bearer " + self.token}) as response:
                    if not response.is_success:
                        raise GatewayError(f"Inspection returned HTTP {response.status_code}.", response.status_code)
                    count = 0
                    for line in response.iter_lines():
                        if line.startswith("data: "):
                            count += 1
                            if count > 256 or len(line) > 262144:
                                raise GatewayError("Inspection stream exceeded its safety limit.")
                            event = json.loads(line[6:])
                            if "error" in event:
                                raise GatewayError("Inspection unavailable: " + str(event["error"]))
                            yield event
        except httpx.HTTPError as exc:
            raise GatewayError("Inspection stream disconnected. The backend result may still finish.") from exc

    def budget(self, identity, workflow_id):
        return self.request("/admin/governance/budget?" + urlencode({**{
            k: v for k, v in identity.items() if v is not None}, "workflow_id": workflow_id}))
