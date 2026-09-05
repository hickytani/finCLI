"""Validated local AI analysis. Model output is always advisory."""
from finguard.ai.model import OllamaModel
from finguard.ai.prompts import EXTRACTION_PROMPT
from finguard.ai.schemas import TransactionExtraction


class LocalAIAnalyzer:
    def __init__(self, model: OllamaModel | None = None):
        self.model = model or OllamaModel()

    def extract(self, request: str) -> TransactionExtraction:
        if len(request) > 4000:
            raise ValueError("Request exceeds the bounded AI input limit")
        return TransactionExtraction.model_validate(self.model.generate_json(EXTRACTION_PROMPT.format(request=request)))
