from __future__ import annotations

import asyncio
import importlib.util
import json

import pytest

from piisafe import PIISafeGuard

LINE = "raj.mehta@corp.com accessed 192.168.1.45"
CLEAN = "MAIL_001 accessed HOST_001"


# ================================================================== LangChain

def _missing(mod: str) -> bool:
    return importlib.util.find_spec(mod) is None


needs_langchain = pytest.mark.skipif(_missing("langchain_core"), reason="langchain-core not installed")
needs_langgraph = pytest.mark.skipif(_missing("langgraph"), reason="langgraph not installed")


@needs_langchain
def test_runnable_sanitises_strings_messages_and_documents(guard):
    from langchain_core.documents import Document
    from langchain_core.messages import HumanMessage

    r = guard.as_runnable()
    assert r.invoke(LINE) == CLEAN
    assert r.invoke({"question": LINE, "n": 3}) == {"question": CLEAN, "n": 3}

    msg = r.invoke(HumanMessage(content=LINE, id="m1"))
    assert msg.content == CLEAN and msg.id == "m1"

    parts = r.invoke(HumanMessage(content=[{"type": "text", "text": LINE}, {"type": "image_url", "image_url": "x"}]))
    assert parts.content[0]["text"] == CLEAN and parts.content[1]["type"] == "image_url"

    doc = r.invoke([Document(page_content="host 192.168.1.45", metadata={"src": "kb"})])[0]
    assert doc.page_content == "host HOST_001" and doc.metadata == {"src": "kb"}


@needs_langchain
def test_runnable_sanitises_prompt_values(guard):
    from langchain_core.prompts import ChatPromptTemplate

    prompt = ChatPromptTemplate.from_messages([("system", "You are a SOC analyst."), ("human", "{q}")])
    out = (prompt | guard.as_runnable()).invoke({"q": LINE})
    assert out.to_messages()[1].content == CLEAN


@needs_langchain
def test_restore_runnable_round_trip(guard):
    from langchain_core.messages import AIMessage

    from piisafe.integrations.langchain import restore_runnable

    guard.on_prompt(LINE)
    assert restore_runnable(guard).invoke(AIMessage(content="Block HOST_001")).content == "Block 192.168.1.45"


@needs_langchain
def test_callback_rejects_raw_pii_and_passes_aliases(guard):
    from langchain_core.language_models.fake_chat_models import FakeListChatModel

    from piisafe.integrations.langchain import UnsanitisedPIIError

    llm = FakeListChatModel(responses=["ok", "ok"])
    cb = guard.as_callback()
    assert llm.invoke(CLEAN, config={"callbacks": [cb]}).content == "ok"
    with pytest.raises(UnsanitisedPIIError) as exc:
        llm.invoke(LINE, config={"callbacks": [cb]})
    assert exc.value.entity_types == ["EMAIL_ADDRESS", "IP_ADDRESS"]
    assert "raj" not in str(exc.value)  # never echoes values


@needs_langchain
def test_callback_check_leaves_session_untouched(guard):
    guard.as_callback(mode="warn")._check([LINE])
    assert guard.registry.records == {}


@needs_langchain
def test_full_chain_model_never_sees_pii(guard):
    from langchain_core.language_models.fake_chat_models import FakeListChatModel
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate

    from piisafe.integrations.langchain import restore_runnable

    seen: list[str] = []

    class Spy(FakeListChatModel):
        def _call(self, messages, *a, **kw):  # noqa: ANN001, ANN002, ANN003, ANN202
            seen.extend(m.content for m in messages)
            return "Block HOST_001 and notify MAIL_001"

    prompt = ChatPromptTemplate.from_messages([("human", "{q}")])
    chain = guard.as_runnable() | prompt | Spy(responses=[""]) | StrOutputParser() | restore_runnable(guard)
    answer = chain.invoke({"q": LINE}, config={"callbacks": [guard.as_callback()]})
    assert seen == [CLEAN]
    assert answer == "Block 192.168.1.45 and notify raj.mehta@corp.com"


# ================================================================== LangGraph


@needs_langgraph
def test_langgraph_node_replaces_messages_in_state(guard):
    from langchain_core.messages import AIMessage, HumanMessage
    from langgraph.graph import END, START, MessagesState, StateGraph

    seen: list[str] = []

    def agent(state: MessagesState) -> dict:
        seen.extend(m.content for m in state["messages"])
        return {"messages": [AIMessage(content="Investigate HOST_001")]}

    g = StateGraph(MessagesState)
    g.add_node("pii_guard", guard.as_langgraph_node())
    g.add_node("agent", agent)
    g.add_edge(START, "pii_guard")
    g.add_edge("pii_guard", "agent")
    g.add_edge("agent", END)
    out = g.compile().invoke({"messages": [HumanMessage(content=LINE)]})

    assert seen == [CLEAN]
    assert [m.content for m in out["messages"]] == [CLEAN, "Investigate HOST_001"]  # raw text not kept


@needs_langgraph
def test_langgraph_node_custom_keys(guard):
    from piisafe.integrations.langgraph import sanitize_node

    node = sanitize_node(guard, keys=("ticket", "missing"))
    assert node({"ticket": LINE, "other": LINE}) == {"ticket": CLEAN}


# ======================================================================== MCP


def _call(server, name: str, args: dict):  # noqa: ANN001, ANN202
    res = asyncio.run(server.call_tool(name, args))
    if isinstance(res, tuple):  # (content, structured) on some SDK versions
        res = res[-1] if isinstance(res[-1], dict) else res[0]
    if isinstance(res, dict):
        return res.get("result", res)
    content = getattr(res, "structured_content", None) or getattr(res, "structuredContent", None)
    if content:
        return content.get("result", content)
    items = getattr(res, "content", res)
    return json.loads(items[0].text)


def _tools(server) -> set[str]:  # noqa: ANN001
    tools = asyncio.run(server.list_tools())
    return {t.name for t in getattr(tools, "tools", tools)}


@pytest.fixture
def mcp_server(state_dir):
    pytest.importorskip("mcp", reason="mcp not installed")
    from piisafe.integrations.mcp import build_server

    servers = []

    def make(**kw):  # noqa: ANN003, ANN202
        s = build_server(state_dir=state_dir, **kw)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.piisafe_pool.clear()


def test_mcp_tools_and_restore_gate(mcp_server):
    assert _tools(mcp_server()) == {"sanitize", "scan", "score_exposure"}
    assert "restore" in _tools(mcp_server(allow_restore=True))


def test_mcp_sanitize_is_consistent_per_session_and_persisted(mcp_server, state_dir):
    s = mcp_server(allow_restore=True)
    r1 = _call(s, "sanitize", {"text": LINE, "session_id": "INC-9"})
    r2 = _call(s, "sanitize", {"text": "again 192.168.1.45", "session_id": "INC-9"})
    assert r1["sanitised_text"] == CLEAN and r2["sanitised_text"] == "again HOST_001"
    assert r1["entities_found"] == {"EMAIL_ADDRESS": 1, "IP_ADDRESS": 1}
    assert _call(s, "restore", {"text": "HOST_001", "session_id": "INC-9"}) == {"text": "192.168.1.45"}

    s.piisafe_pool.clear()
    with PIISafeGuard(session_id="INC-9", state_dir=state_dir) as g:  # same state as CLI / dashboard
        assert g.restore("MAIL_001") == "raj.mehta@corp.com"


def test_mcp_scan_and_score_never_return_values(mcp_server, state_dir):
    s = mcp_server()
    scan = _call(s, "scan", {"text": LINE})
    score = _call(s, "score_exposure", {"text": LINE})
    assert scan["count"] == 2 and score["risk_score"] > 0
    blob = json.dumps([scan, score])
    assert "raj.mehta" not in blob and "192.168.1.45" not in blob
    with PIISafeGuard(session_id="mcp-default", state_dir=state_dir) as g:
        assert g.registry.records == {}  # dry runs persist nothing


def test_mcp_rejects_bad_input(mcp_server):
    s = mcp_server(allow_restore=True)

    def error(name: str, args: dict) -> str:
        with pytest.raises(Exception) as exc:
            _call(s, name, args)
        return f"{exc.value} {exc.value.__cause__}"

    assert "session_id" in error("sanitize", {"text": "x", "session_id": "../etc"})
    assert "not found" in error("restore", {"text": "USER_001", "session_id": "never-created"})
