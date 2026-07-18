# BugBîner AI — Configuration Manager
# Author: Joudi Janble

import json
import os

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "..", "config.json")


_DEFAULTS = {
    # Ollama (local LLM) settings — the only provider (local model only)
    "ollama_enabled": True,
    "ollama_base": "http://localhost:11434",
    "ollama_model": "qwen2.5:7b",      # scan + chat model (same model, parallel channels)
    "vision_model": "",                # vision model for images ("" = auto-detect, e.g. qwen2.5vl)
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
            json.dump(existing, f, indent=2)
        return True
    except Exception:
        return False
