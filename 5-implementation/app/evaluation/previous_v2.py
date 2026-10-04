"""Reproduce the CURRENT-at-start implementation from its frozen main-repo snapshot."""
import hashlib
import importlib
import sys
import types
import zipfile

from app.settings import ROOT


def detectors(snapshot=None):
    source=ROOT/(snapshot or "artifacts/iteration2/previous-source.zip")
    if not source.resolve().is_relative_to(ROOT.resolve()):
        raise ValueError("Previous snapshot must be inside this repository")
    destination=ROOT/".tools"/("previous-"+hashlib.sha256(source.read_bytes()).hexdigest()[:16])
    destination.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(source) as archive:
        for info in archive.infolist():
            path=destination/info.filename
            if not path.resolve().is_relative_to(destination.resolve()):
                raise ValueError("Invalid archived source path")
            if path.suffix==".py":
                value=archive.read(info).decode("utf-8").replace("from app.","from previous.").replace("import app.","import previous.")
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(value,encoding="utf-8")
            elif info.filename.startswith("config/"):
                path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(archive.read(info))
    package=types.ModuleType("previous")
    package.__path__=[str(destination/"app")]
    sys.modules["previous"]=package
    rules=importlib.import_module("previous.controls.prompt_patterns")
    provider=importlib.import_module("previous.semantic.deberta")
    normalization=importlib.import_module("previous.controls.normalization")
    return rules.inspect,provider.DebertaProvider,normalization.inspection_views,hashlib.sha256(source.read_bytes()).hexdigest()
