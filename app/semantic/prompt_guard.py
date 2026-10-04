import asyncio
import time
from pathlib import Path

from app.controls.context import discussion_context
from app.controls.normalization import inspection_views
from app.controls.reconstruction import semantic_units
from app.detection.trace import active_trace, emit, text_hash
from app.semantic.base import SemanticRisk, SemanticUnavailable


class PromptGuardProvider:
    """Prompt Guard 2 binary classifier with overlapping windows; local weights only."""
    provider_id = "prompt_guard"
    preprocessing_version = "inspection-views-v3/context-v3"
    max_input_chars = 65536
    max_tokens = 16384
    max_windows = 40

    def __init__(self, path: str, cpu_threads: int = 2):
        self.path = path
        self.cpu_threads = cpu_threads
        self.tokenizer = self.model = None
        self._inflight = None
        self.last_details = {}
        self._contexts = []

    def _load(self):
        if not Path(self.path).is_dir():
            raise SemanticUnavailable("Prompt Guard weights are not installed")
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        torch.set_num_threads(self.cpu_threads)

        self.tokenizer = AutoTokenizer.from_pretrained(self.path, local_files_only=True, trust_remote_code=False)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.path, local_files_only=True,
            trust_remote_code=False, use_safetensors=True)
        self.model.eval()

    def _analyze(self, texts):
        if sum(len(text) for text in texts) > self.max_input_chars:
            raise SemanticUnavailable("Semantic character budget exceeded")
        import torch
        if self.model is None:
            self._load()
        score = raw_score = 0.0
        total_tokens = total_windows = 0
        prepared = []
        # Normalize inspection views, preserving each leaf's provenance. Deduplicate within a request.
        seen = set()
        windows_meta=[]
        preparation_start=time.perf_counter()
        for input_index,text in enumerate(texts):
            views = inspection_views(text)
            # Classify decoded meaning with its surrounding instructions. Encoded tokens alone
            # caused false positives on benign Base64; retain originals only in rule evidence.
            for view in (views[-1],):
                if not view.text or view.text in seen:
                    continue
                seen.add(view.text)
                kwargs={"return_offsets_mapping":True} if active_trace.get() is not None and getattr(self.tokenizer,"is_fast",False) else {}
                tokens = self.tokenizer(view.text, return_tensors="pt", truncation=True,
                    max_length=512, stride=64, return_overflowing_tokens=True, padding=True,**kwargs)
                tokens.pop("overflow_to_sample_mapping", None)
                offsets=tokens.pop("offset_mapping",None)
                windows = len(tokens["input_ids"])
                total_windows += windows
                total_tokens += int(tokens["attention_mask"].sum())
                if total_windows > self.max_windows or total_tokens > self.max_tokens:
                    raise SemanticUnavailable("Semantic token/window budget exceeded")
                trusted = self._contexts[input_index] if input_index<len(self._contexts) else False
                discussion=discussion_context(view.text,trusted)
                prepared.append((tokens,view,discussion,offsets,input_index))
        emit("ai_input",{"model":self.provider_id,"tokenizer":type(self.tokenizer).__name__,
            "characters":sum(map(len,texts)),"tokens":total_tokens,"windows":total_windows,
            "worker_admitted":True},(time.perf_counter()-preparation_start)*1000)
        window_number=0
        preparation_ms=(time.perf_counter()-preparation_start)*1000
        inference_ms=0
        for tokens,view,discussion,offsets,input_index in prepared:
            for offset in range(0, len(tokens["input_ids"]), 8):
                batch_start=time.perf_counter()
                with torch.inference_mode():
                    logits = self.model(**{k: v[offset : offset + 8] for k, v in tokens.items()}).logits
                    # Prompt Guard 2's malicious class is index 1; reject incompatible model weights.
                    if logits.shape[-1] != 2:
                        raise SemanticUnavailable("Expected Prompt Guard 2 binary classifier")
                    probabilities=torch.softmax(logits, dim=-1)[:, 1]
                    batch_ms=(time.perf_counter()-batch_start)*1000
                    inference_ms+=batch_ms
                    for local,value in enumerate(probabilities):
                        raw=float(value)
                        # Preserve raw model evidence. Only explicit bounded quoted-data
                        # context changes the effective signal; no phrase-specific whitelist.
                        effective=min(raw,.02) if discussion else raw
                        raw_score=max(raw_score,raw)
                        score=max(score,effective)
                        n=offset+local
                        count=int(tokens["attention_mask"][n].sum())
                        meta={"window":window_number,"input_index":input_index,"token_start":n*446,"token_end":n*446+count,
                            "tokens":count,"raw_score":raw,"score":effective,
                            "context":"security_discussion" if discussion else "instruction_or_undetermined",
                            "label":"injection" if raw>=.5 else "safe", "batch_latency_ms":batch_ms,
                            "view_sha256":text_hash(view.text),"transformations":list(view.transformations)}
                        if offsets is not None:
                            spans=[pair.tolist() for pair in offsets[n] if int(pair[1])>int(pair[0])]
                            if spans:
                                a,b=spans[0][0],spans[-1][1]
                                meta.update(source_start=a,source_end=b,offset_space="normalized inspection view")
                                emit("ai_window",meta|{"excerpt":view.text[a:b]})
                            else:
                                emit("ai_window",meta)
                        else:
                            emit("ai_window",meta)
                        windows_meta.append(meta)
                        window_number+=1
        self.last_details={"raw_score":raw_score,"effective_score":score,"context_adjusted":score!=raw_score,
            "artifact_sha256":getattr(self,"model_artifact_sha256",None),
            "preparation_ms":preparation_ms,"inference_ms":inference_ms,
            "characters":sum(map(len,texts)),"token_count":total_tokens,"window_count":total_windows,
            "windows":windows_meta,"window_latency_semantics":"Batch time shared by windows; per-window compute is not separately measured"}
        emit("ai_score",self.last_details)
        return SemanticRisk(prompt_injection=score)

    async def analyze(self, transaction):
        if self._inflight is not None and not self._inflight.done():
            raise SemanticUnavailable("Prompt Guard is busy")
        before=time.perf_counter()
        units=semantic_units(transaction)
        reconstruction_ms=(time.perf_counter()-before)*1000
        self._contexts=[transaction.context.source_trust=="trusted" and u.role in {"user","data"}
            for u in units]
        self._inflight = asyncio.create_task(asyncio.to_thread(self._analyze,[u.text for u in units]))
        self._inflight.add_done_callback(lambda task: task.exception() if not task.cancelled() else None)
        try:
            # A timeout does not create unlimited background inference jobs.
            result=await asyncio.shield(self._inflight)
            self.last_details["reconstruction_ms"]=reconstruction_ms
            transaction.metadata["semantic_details"]=self.last_details
            return result
        except Exception as exc:
            raise SemanticUnavailable("Prompt Guard inference unavailable") from exc
