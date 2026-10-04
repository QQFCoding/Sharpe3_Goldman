import pytest

from cloud import runtime


def test_cloud_requires_explicit_standalone_opt_in(monkeypatch):
    monkeypatch.delenv("AICL_CLOUD_STANDALONE", raising=False)
    with pytest.raises(RuntimeError, match="explicit"):
        runtime.start_cloud_runtime()


def test_pinned_model_mismatch_never_falls_back(tmp_path, monkeypatch):
    model = tmp_path / "models/deberta"
    model.mkdir(parents=True)
    (model / "model.safetensors").write_bytes(b"invalid synthetic weights")
    for name in ("config.json", "tokenizer_config.json", "spm.model"):
        (model / name).write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(runtime, "ROOT", tmp_path)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **kw: None)
    with (tmp_path / "log.txt").open("w", encoding="utf-8") as log:
        with pytest.raises(RuntimeError, match="checksum"):
            runtime.ensure_model(log)


def test_free_port_is_loopback_bindable():
    import socket
    port = runtime.free_port()
    with socket.socket() as check:
        check.bind(("127.0.0.1", port))
    assert 1024 <= port <= 65535


def test_occupied_port_is_refused_without_disturbing_existing_service():
    import socket
    with socket.socket() as existing:
        existing.bind(("127.0.0.1", 0))
        existing.listen()
        port = existing.getsockname()[1]
        with pytest.raises(RuntimeError, match="occupied"):
            runtime.start_demo(gateway_port=port, download=False)
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            connection, _ = existing.accept()
            connection.close()


def test_partial_process_launch_failure_cleans_up_only_owned_children(monkeypatch):
    owned = []
    stopped = []
    class Child:
        def __init__(self, pid):
            self.pid = pid
        def poll(self):
            return None
    def launch(*args, **kwargs):
        if len(owned) == 2:
            raise OSError("Synthetic launch failure")
        child = Child(900000 + len(owned))
        owned.append(child)
        return child
    monkeypatch.setattr(runtime, "ensure_model", lambda *args, **kwargs: None)
    monkeypatch.setattr(runtime.subprocess, "Popen", launch)
    monkeypatch.setattr(runtime, "stop_owned_process", lambda child: stopped.append(child.pid))
    with pytest.raises(OSError, match="Synthetic"):
        runtime.start_demo(download=False)
    assert stopped == [child.pid for child in reversed(owned)]


def test_runtime_representation_excludes_operator_secret():
    secret = "synthetic-private-operator-credential"
    resource = runtime.CloudRuntime("http://127.0.0.1:9000", secret, [], None, None)
    assert secret not in repr(resource)
    assert resource.token == secret
