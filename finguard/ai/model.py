"""Minimal standard-library client for the locally running Ollama API."""
import json
import urllib.error
import urllib.request


class LocalModelError(RuntimeError):
    pass


class OllamaModel:
    def __init__(self, model: str = "qwen3:0.6b", endpoint: str = "http://127.0.0.1:11434", timeout_seconds: int = 180):
        self.model, self.endpoint, self.timeout_seconds = model, endpoint.rstrip("/"), timeout_seconds

    def generate_json(self, prompt: str) -> dict:
        payload = json.dumps({"model": self.model, "stream": False, "format": "json", "think": False, "options": {"temperature": 0, "num_predict": 300}, "messages": [{"role": "user", "content": prompt}]}).encode()
        request = urllib.request.Request(f"{self.endpoint}/api/chat", data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read().decode())
            content = body["message"]["content"]
            if not isinstance(content, str):
                raise ValueError("Ollama response content was not text")
            parsed = json.loads(content)
            if not isinstance(parsed, dict):
                raise ValueError("Ollama response was not a JSON object")
            return parsed
        except (urllib.error.URLError, TimeoutError, KeyError, ValueError) as exc:
            raise LocalModelError(f"Local model unavailable or returned invalid JSON: {exc}") from exc

    def status(self) -> dict:
        """Return only local runtime/model availability; never performs inference."""
        request = urllib.request.Request(f"{self.endpoint}/api/tags", method="GET")
        try:
            with urllib.request.urlopen(request, timeout=min(self.timeout_seconds, 5)) as response:
                models = json.loads(response.read().decode()).get("models", [])
            installed = any(item.get("name") == self.model for item in models)
            return {"runtime": "ollama", "endpoint": self.endpoint, "model": self.model, "available": installed}
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            return {"runtime": "ollama", "endpoint": self.endpoint, "model": self.model, "available": False, "error": type(exc).__name__}
