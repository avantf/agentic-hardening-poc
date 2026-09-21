"""Tests for agent.llm_client. No real model or network is ever contacted."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from agent import llm_client
from agent.llm_client import (
    AnthropicClient,
    LLMClient,
    LLMConfigError,
    LLMRequestError,
    LLMResponseError,
    LocalOllamaClient,
    get_llm_client,
)
from agent.models import Finding

CLASSES = ["change_ssh_policy", "rotate_credential"]
GOOD_REPLY = '{"action_class": "change_ssh_policy", "rationale": "Disable password auth."}'
FINDING = Finding(
    id="F-1",
    control_id="BC-005",
    service="jump-host",
    description="PasswordAuthentication is yes",
    severity="high",
    source="baseline",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for var in ("LLM_PROVIDER", "OLLAMA_MODEL", "OLLAMA_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def post(monkeypatch):
    """Replace requests.post; tests set post.side_effect / post.return_value."""
    mock = MagicMock()
    monkeypatch.setattr(llm_client.requests, "post", mock)
    return mock


def ollama_response(content: str) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {"message": {"content": content}}
    return response


# --- factory -----------------------------------------------------------------


def test_default_provider_is_local(post):
    client = get_llm_client()
    assert isinstance(client, LocalOllamaClient)
    assert isinstance(client, LLMClient)
    post.assert_not_called()  # building the client must not contact the model


def test_provider_read_from_environment(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "cloud")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert isinstance(get_llm_client(), AnthropicClient)


def test_explicit_argument_overrides_environment(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "cloud")
    assert isinstance(get_llm_client("local"), LocalOllamaClient)


def test_provider_name_is_case_insensitive(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert isinstance(get_llm_client(" Cloud "), AnthropicClient)


def test_cloud_without_api_key_raises():
    with pytest.raises(LLMConfigError, match="ANTHROPIC_API_KEY"):
        get_llm_client("cloud")


def test_unknown_provider_raises():
    with pytest.raises(LLMConfigError, match="openai"):
        get_llm_client("openai")


def test_ollama_model_default_and_override(monkeypatch):
    assert get_llm_client("local").model == "llama3.1:8b"
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")
    assert get_llm_client("local").model == "qwen2.5:7b"


# --- LocalOllamaClient -------------------------------------------------------


def test_ollama_request_forces_json_and_returns_proposal(post, monkeypatch):
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5:7b")
    post.return_value = ollama_response(GOOD_REPLY)

    result = LocalOllamaClient().propose_action(FINDING, CLASSES)

    assert result == {"action_class": "change_ssh_policy", "rationale": "Disable password auth."}
    url = post.call_args.args[0]
    payload = post.call_args.kwargs["json"]
    assert url == "http://localhost:11434/api/chat"
    assert payload["format"] == "json"
    assert payload["model"] == "qwen2.5:7b"
    assert payload["stream"] is False


def test_ollama_retries_on_unparsable_output(post):
    post.side_effect = [ollama_response("Sure! I would..."), ollama_response(GOOD_REPLY)]

    result = LocalOllamaClient().propose_action(FINDING, CLASSES)

    assert result["action_class"] == "change_ssh_policy"
    assert post.call_count == 2
    # the retry tells the model what was wrong with its previous reply
    retry_messages = post.call_args_list[1].kwargs["json"]["messages"]
    assert "invalid" in retry_messages[-1]["content"]


def test_action_class_outside_allowed_list_is_rejected(post):
    bad = '{"action_class": "delete_everything", "rationale": "x"}'
    post.return_value = ollama_response(bad)

    with pytest.raises(LLMResponseError, match="delete_everything"):
        LocalOllamaClient(max_attempts=3).propose_action(FINDING, CLASSES)
    assert post.call_count == 3


def test_json_in_code_fence_is_accepted(post):
    post.return_value = ollama_response(f"```json\n{GOOD_REPLY}\n```")
    assert LocalOllamaClient().propose_action(FINDING, CLASSES)["action_class"] == "change_ssh_policy"


def test_connection_error_is_not_retried(post):
    post.side_effect = requests.ConnectionError("refused")
    with pytest.raises(LLMRequestError):
        LocalOllamaClient().propose_action(FINDING, CLASSES)
    assert post.call_count == 1


def test_empty_action_class_list_raises(post):
    with pytest.raises(ValueError):
        LocalOllamaClient().propose_action(FINDING, [])
    post.assert_not_called()


# --- AnthropicClient ---------------------------------------------------------


def anthropic_client(monkeypatch, *replies: SimpleNamespace) -> AnthropicClient:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = AnthropicClient()
    client._client = MagicMock()
    client._client.messages.create.side_effect = list(replies)
    return client


def anthropic_reply(text: str, stop_reason: str = "end_turn") -> SimpleNamespace:
    return SimpleNamespace(stop_reason=stop_reason, content=[SimpleNamespace(type="text", text=text)])


def test_anthropic_returns_proposal(monkeypatch):
    client = anthropic_client(monkeypatch, anthropic_reply(GOOD_REPLY))

    result = client.propose_action(FINDING, CLASSES)

    assert result["action_class"] == "change_ssh_policy"
    kwargs = client._client.messages.create.call_args.kwargs
    assert kwargs["model"] == "claude-opus-5"
    assert "temperature" not in kwargs


def test_anthropic_refusal_raises_without_retry(monkeypatch):
    client = anthropic_client(monkeypatch, anthropic_reply("", stop_reason="refusal"))
    with pytest.raises(LLMResponseError, match="refused"):
        client.propose_action(FINDING, CLASSES)
    assert client._client.messages.create.call_count == 1
