# Model card

Hardware inspection detected an NVIDIA GeForce RTX 3050 Laptop GPU with 6 GB
VRAM. System RAM and free disk space could not be queried in the restricted
environment, and no supported local model runtime/library was installed
(`torch`, `transformers`, `llama_cpp`, and `ollama` were absent). No
local/open-weight model is therefore configured. `TreasuryAgent`
uses a constrained deterministic parser as an honest fallback and labels its
model as `not-configured`; it is not LLM inference. Fine-tuning was not
performed because no base model, dataset, or training hardware/configuration
was supplied. A future adapter must produce validated structured output and is
still confined to the SDK allowlist.
