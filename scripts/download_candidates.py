"""Explicit immutable, safetensors-only exploratory downloads inside this repository."""
import hashlib
import json

import httpx

from app.settings import ROOT

MODELS = {
    "deepset": ("deepset/deberta-v3-base-injection", "80dda00d0b0d9a03917a7685e2ddbcd28e04dbb1"),
    "distilbert": ("fmops/distilbert-prompt-injection", "c5da1fefd33c98c447b50dd806fe86aeb9e8c26c"),
}


def main():
    with httpx.Client(follow_redirects=True,timeout=90) as client:
        for name,(repo,revision) in MODELS.items():
            response=client.get(f"https://huggingface.co/api/models/{repo}/revision/{revision}?blobs=true")
            response.raise_for_status()
            meta=response.json()
            destination=ROOT/"models"/name
            destination.mkdir(parents=True,exist_ok=True)
            files={}
            for entry in meta["siblings"]:
                filename=entry["rfilename"]
                if filename not in {"config.json","model.safetensors","tokenizer.json","tokenizer_config.json",
                    "special_tokens_map.json","spm.model","vocab.txt","README.md","added_tokens.json"}:
                    continue
                output=destination/filename
                if not output.is_file():
                    temporary=output.with_suffix(output.suffix+".download")
                    url=f"https://huggingface.co/{repo}/resolve/{revision}/{filename}?download=true"
                    with client.stream("GET",url) as response,temporary.open("wb") as stream:
                        response.raise_for_status()
                        for chunk in response.iter_bytes(1024*1024):
                            stream.write(chunk)
                    temporary.replace(output)
                with output.open("rb") as stream:
                    sha=hashlib.file_digest(stream,"sha256").hexdigest()
                if entry.get("lfs",{}).get("sha256") and sha!=entry["lfs"]["sha256"]:
                    raise ValueError("Pinned artifact integrity mismatch")
                files[filename]=sha
                print(name,filename,output.stat().st_size,flush=True)
            (ROOT/f"config/{name}.lock.json").write_text(json.dumps({"repo":repo,"revision":revision,
                "license":meta.get("cardData",{}).get("license"),"files":files},indent=2)+"\n")
            print("INSTALLED",name,json.loads((destination/"config.json").read_text()).get("id2label"),flush=True)


if __name__=="__main__":
    main()
