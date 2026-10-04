from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider


def create_tracer(endpoint: str | None):
    provider = TracerProvider(resource=Resource.create({"service.name": "ai-control-layer"}))
    if endpoint:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, timeout=3)))
    return provider, provider.get_tracer("aicl")
