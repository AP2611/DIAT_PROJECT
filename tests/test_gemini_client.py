from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulntriage.gemini_client import GeminiClient, GeminiError


def _fake_response(status: int, body: dict):
    return SimpleNamespace(
        status_code=status,
        text=str(body),
        json=lambda: body,
    )


def _client() -> GeminiClient:
    return GeminiClient(api_key="test-key", model="gemini-3.1-flash-lite")


def test_missing_api_key_raises():
    with pytest.raises(GeminiError, match="GEMINI_API_KEY"):
        GeminiClient(api_key="")


def test_chat_builds_structured_payload_and_parses(monkeypatch):
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["payload"] = kwargs["json"]
        return _fake_response(
            200,
            {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {
                                    "text": (
                                        '{"p_vulnerable":0.7,"cwe_id":null,"reasoning":"x",'
                                        '"evidence":[],"limitations":"none"}'
                                    )
                                }
                            ]
                        }
                    }
                ],
                "usageMetadata": {"promptTokenCount": 100, "candidatesTokenCount": 40},
            },
        )

    monkeypatch.setattr("vulntriage.gemini_client.httpx.post", fake_post)
    response = _client().chat(
        [
            {"role": "system", "content": "SYSTEM"},
            {"role": "user", "content": "USER"},
        ]
    )

    assert captured["url"].endswith("models/gemini-3.1-flash-lite:generateContent")
    payload = captured["payload"]
    assert payload["systemInstruction"]["parts"][0]["text"] == "SYSTEM"
    assert payload["contents"][0] == {"role": "user", "parts": [{"text": "USER"}]}
    gen = payload["generationConfig"]
    assert gen["responseMimeType"] == "application/json"
    assert "p_vulnerable" in gen["responseJsonSchema"]["properties"]
    assert response.parsed is not None
    assert response.parsed.p_vulnerable == 0.7
    assert response.prompt_eval_count == 100
    assert response.eval_count == 40


def test_http_error_becomes_gemini_error(monkeypatch):
    monkeypatch.setattr(
        "vulntriage.gemini_client.httpx.post",
        lambda *a, **k: _fake_response(400, {"error": {"message": "bad request"}}),
    )
    with pytest.raises(GeminiError, match="HTTP 400"):
        _client().chat([{"role": "user", "content": "hi"}])
