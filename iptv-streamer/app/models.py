# app/models.py
import json
import os
from threading import Lock

DATA_DIR = "data"
CHANNELS_FILE = os.path.join(DATA_DIR, "channels.json")

os.makedirs(DATA_DIR, exist_ok=True)

class ChannelManager:
    def __init__(self):
        self.channels = {}
        self.lock = Lock()
        self.load()  # ← This must exist!

    def _normalize_channel(self, ch):
        if "sources" not in ch:
            ch["sources"] = []
        for s in ch["sources"]:
            if "enabled" not in s:
                s["enabled"] = True
        return ch

    def load(self):
        """Load channels from JSON file."""
        try:
            if os.path.exists(CHANNELS_FILE):
                with open(CHANNELS_FILE, 'r') as f:
                    raw = json.load(f)
                    self.channels = {k: self._normalize_channel(v) for k, v in raw.items()}
            else:
                self.channels = {}
                self.save()  # Create empty file
        except Exception as e:
            print(f"[ERROR] Failed to load {CHANNELS_FILE}: {e}")
            self.channels = {}
            self.save()

    def save(self):
        """Save channels to JSON file."""
        with self.lock:
            try:
                with open(CHANNELS_FILE, 'w') as f:
                    json.dump(self.channels, f, indent=2)
            except Exception as e:
                print(f"[ERROR] Failed to save {CHANNELS_FILE}: {e}")

    def get_channel(self, key):
        return self.channels.get(key)

    def add_channel(self, key, name, sources):
        self.channels[key] = {"name": name, "sources": sources}
        self.save()

    def update_channel(self, key, name, sources):
        self.channels[key] = {"name": name, "sources": sources}
        self.save()

    def delete_channel(self, key):
        self.channels.pop(key, None)
        self.save()

    def list_channels(self):
        return dict(self.channels)

    def move_source(self, key, idx_from, idx_to):
        ch = self.channels[key]
        src = ch["sources"].pop(idx_from)
        ch["sources"].insert(idx_to, src)
        self.save()

    def toggle_source(self, key, idx):
        ch = self.channels[key]
        ch["sources"][idx]["enabled"] = not ch["sources"][idx]["enabled"]
        self.save()
