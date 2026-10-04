"""Path checks apply to file-tool arguments, not legitimate security discussions."""
import re
from pathlib import Path

from app.controls.normalization import InspectionLimit, inspection_views
from app.core.transaction import Finding, Operation

DEVICES=re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)",re.I)


def unsafe_lexical_path(value):
    value=value.replace("\\","/")
    parts=value.split("/")
    return (".." in parts or value.startswith(("/","~")) or any(":" in p or "\x00" in p
        or p.endswith(("."," ")) or DEVICES.match(p) for p in parts))


def workspace_path(root,relative):
    """Local file-server preflight helper; the executor must also prevent races.

    Remote MCP workspace confinement must be enforced by that server. This helper
    does not turn a gateway's lexical path check into remote filesystem authority.
    """
    if unsafe_lexical_path(relative):
        raise ValueError("Unsafe workspace path")
    base=Path(root).resolve(strict=True)
    target=base
    for part in relative.replace("\\","/").split("/"):
        target=target/part
        if target.is_symlink() or target.is_junction():
            raise ValueError("Workspace symlink/junction denied")
    resolved=target.resolve(strict=False)
    if not resolved.is_relative_to(base):
        raise ValueError("Workspace escape")
    return resolved


def inspect(tx):
    if tx.operation not in {Operation.TOOL_CALL, Operation.MCP_TOOL_CALL} or not tx.resource:
        return []
    if "filesystem." not in tx.resource.name or not isinstance(tx.payload, dict):
        return []
    path = tx.payload.get("path")
    if not isinstance(path, str):
        return []
    try:
        unsafe=unsafe_lexical_path(path) or any(unsafe_lexical_path(view.text) for view in inspection_views(path))
    except InspectionLimit:
        unsafe=True
    if unsafe:
            return [Finding(code="UNSAFE_FILE_PATH", control="tool-path", rule_id="TOOL_PATH_001",
                category="path_traversal", title="File path leaves the relative workspace",
                remediation="Use a relative path within the tool's configured workspace.")]
    return []
