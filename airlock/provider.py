from __future__ import annotations
import os, time

class ProviderUnavailable(RuntimeError): pass

class NebiusClient:
    def __init__(self):
        self.api_key = os.getenv("NEBIUS_API_KEY"); self.base_url = os.getenv("NEBIUS_TOKEN_FACTORY_BASE_URL", "https://api.tokenfactory.nebius.com/v1")
        self.planner_model = os.getenv("AIRLOCK_PLANNER_MODEL", "nvidia/nemotron-3-ultra-550b-a12b")
        self.reader_model = os.getenv("AIRLOCK_READER_MODEL", "nvidia/nemotron-3-nano-30b-a3b")
    def chat(self, messages, model: str, timeout: float = 30):
        if not self.api_key: raise ProviderUnavailable("NEBIUS_API_KEY is not configured; use offline mode")
        from openai import OpenAI
        started = time.perf_counter(); client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=timeout, max_retries=1)
        response = client.chat.completions.create(model=model, messages=messages, temperature=0, max_tokens=800)
        return {"text": response.choices[0].message.content, "model": model, "provider": "Nebius Token Factory", "latency_ms": round((time.perf_counter()-started)*1000), "id": response.id}
