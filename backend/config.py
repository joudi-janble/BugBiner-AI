# BugBîner AI — Configuration Manager
# Author: Joudi Janble

import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "config.json")


_DEFAULTS = {
    # ── Active AI provider (nothing is downloaded/requested at startup) ──
    #   ollama    → local models
    #   openai    → any OpenAI-compatible API (OpenAI, OpenRouter, Groq, DeepSeek, ...)
    #   anthropic → Claude
    #   gemini    → Google Gemini
    #   zai       → Z.AI / GLM (OpenAI-compatible, https://api.z.ai/api/paas/v4)
    "ai_provider": "ollama",
    "ai_base_url": "",                 # empty → provider default (Ollama: ollama_base)
    "ai_api_key": "",
    "ai_model": "",                    # empty → ollama_model for Ollama / provider default otherwise
    "chat_model": "",                  # empty → ai_model
    "ai_temperature": 0.15,
    "ai_num_ctx": 4096,
    "ai_max_tokens": 3000,
    "ai_headers": {},

    # ── Legacy Ollama fields (kept for compatibility) ──
    "ollama_enabled": True,
    "ollama_base": "http://localhost:11434",
    "ollama_model": "qwen2.5:7b",      # local scan + chat model
    "vision_model": "",                # vision model for images ("" = auto)

    # ── Vulnerability catalog ──
    "vuln_catalog_url": "",            # optional remote catalog (JSON) for updates
    "vuln_catalog_updated": "",
}


def load_config() -> dict:
    if not os.path.exists(CONFIG_FILE):
        return dict(_DEFAULTS)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Merge with defaults so new fields are always present
        merged = dict(_DEFAULTS)
        merged.update(data)
        return merged
    except Exception:
        return dict(_DEFAULTS)


def save_config(data: dict) -> bool:
    try:
        existing = load_config()
        existing.update({k: v for k, v in data.items() if v is not None})
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False
