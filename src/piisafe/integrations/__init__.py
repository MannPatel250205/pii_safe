"""Agent-framework integrations. Each module needs its framework installed:

    piisafe.integrations.langchain   pip install 'piisafe[langchain]'
    piisafe.integrations.langgraph   pip install 'piisafe[langgraph]'
    piisafe.integrations.mcp         pip install 'piisafe[mcp]'   (or: piisafe mcp)

They all wrap one PIISafeGuard, so aliases stay consistent across the CLI,
the dashboard, the REST API and every agent that shares a session id.
"""
