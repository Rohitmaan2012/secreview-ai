import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parent
FIXTURES = ROOT / "fixtures"


class FakeStream:
    def __init__(self, payload, record):
        self.payload = payload
        self.record = record

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get_final_message(self):
        return SimpleNamespace(
            content=[SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=json.dumps(self.payload))],
            stop_reason="end_turn", model="claude-opus-5-5",
            usage=SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=10, cache_creation_input_tokens=5),
        )


class FakeClient:
    """Returns queued JSON payloads in order and records request params."""

    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    def _stream(self, **params):
        self.calls.append(params)
        return FakeStream(self.payloads.pop(0), self.calls)


@pytest.fixture
def fake_client_factory():
    return FakeClient
