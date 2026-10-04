"""Bounded inspection-only groups preserving message role and sibling provenance."""
from dataclasses import dataclass

from app.controls.normalization import InspectionLimit, inspection_views
from app.core.transaction import text_leaves


@dataclass(frozen=True)
class InputUnit:
    text: str
    path: tuple
    origins: tuple = ()
    reconstructed: bool = False
    role: str = "data"


def input_units(tx, keys=True):
    units, chars = [], 0
    excluded = {tuple(p) for p in tx.metadata.get("semantic_trusted_paths", [])}
    for path,text in text_leaves(tx.payload):
        if path in excluded or (len(path)==3 and path[0]=="messages" and path[-1]=="role") or path in {("source",),("classification",)}:
            continue
        chars += len(text)
        if len(units) >= 512 or chars > 65536:
            raise InspectionLimit("Inspection leaf/character budget exceeded")
        role = "data"
        if len(path)==3 and path[0]=="messages" and path[-1]=="content":
            role = tx.payload["messages"][path[1]].get("role", "unknown")
        units.append(InputUnit(text,path,(path,),False,role))
    groups = []
    # Adjacent short messages of the SAME role, never trusted system + untrusted tool.
    messages = tx.payload.get("messages",[]) if isinstance(tx.payload,dict) else []
    if not isinstance(messages,list):
        raise InspectionLimit("Malformed conversation")
    run = []
    def join(items):
        # Decode short leaves before joining. Encoding alphabets and role metadata
        # must not become an accidental opaque model input when fragments combine.
        return " ".join(inspection_views(u.text)[-1].text for u in items)
    def flush():
        if len(run)>1:
            groups.append(InputUnit(join(run),run[0].path,
                tuple(u.path for u in run),True,run[0].role))
        run.clear()
    by_path = {u.path:u for u in units}
    for i,m in enumerate(messages):
        u = by_path.get(("messages",i,"content"))
        if not u or len(u.text)>160 or (run and (u.role!=run[-1].role or len(run)>=8)):
            flush()
        if u and len(u.text)<=160:
            run.append(u)
    flush()
    # Same immediate parent object/array: only short fragments, max 8 per group.
    siblings = {}
    for u in units:
        fragment_container=bool(u.path and u.path[:-1] and u.path[-2] in {"fragments","parts","segments"})
        if u.role=="data" and u.path and len(u.text)<=(6000 if fragment_container else 160):
            siblings.setdefault(u.path[:-1],[]).append(u)
    for parent,items in siblings.items():
        budget=16000 if parent and parent[-1] in {"fragments","parts","segments"} else 1024
        if 2 <= len(items) <= 8 and sum(len(u.text) for u in items)<=budget:
            groups.append(InputUnit(join(items),parent,
                tuple(u.path for u in items),True,"data"))
    if len(groups)>32:
        raise InspectionLimit("Reconstruction group budget exceeded")
    if keys:
        # String-valued keys can carry directives too; never scan protocol metadata keys.
        stack=[((),tx.payload)]
        while stack:
            path,value=stack.pop()
            if len(path)>16:
                raise InspectionLimit("Inspection depth exceeded")
            if isinstance(value,dict):
                for key,item in value.items():
                    if len(str(key))>20 and any(c.isspace() for c in str(key)):
                        units.append(InputUnit(str(key),(*path,"[key]"),((*path,"[key]"),)))
                    stack.append(((*path,key),item))
            elif isinstance(value,list):
                stack.extend(((*path,i),v) for i,v in enumerate(value))
            if len(stack)>1024 or len(units)>544:
                raise InspectionLimit("Inspection structure budget exceeded")
    return units+groups


def semantic_units(tx):
    units=input_units(tx,keys=True)
    grouped={p for u in units if u.reconstructed for p in u.origins}
    return [u for u in units if u.reconstructed or u.path not in grouped]
