"""MCP server: expose guardkit to AI assistants (Claude Desktop, Claude Code, Cursor, ...).

    pip install "guardkit[mcp]"
    guardkit-mcp --policy policy.yaml          # stdio server

Tools: scan_input, scan_output, redact, list_guards. Results contain the action, the (redacted)
text and finding metadata (guard, rule, span, score); matched values are never echoed back.
"""
import argparse
import sys
from typing import Any, Callable, Dict, Optional

from .pipeline import GUARDS, Pipeline
from .policy import from_dict

DEFAULT_POLICY: Dict[str, Any] = {
    "input": [{"guard": "injection", "action": "block"},
              {"guard": "secrets", "action": "redact"},
              {"guard": "pii", "action": "redact"}],
    "output": [{"guard": "secrets", "action": "redact"},
               {"guard": "pii", "action": "redact"}],
}
_REDACT_ONLY: Dict[str, Any] = {"input": [{"guard": "secrets", "action": "redact"},
                                          {"guard": "pii", "action": "redact"}]}


def build_tools(pipeline: Pipeline) -> Dict[str, Callable[..., Dict[str, Any]]]:
    """Plain functions behind the MCP tools (importable and testable without `mcp`)."""
    redactor = from_dict(_REDACT_ONLY)

    def scan_input(text: str) -> Dict[str, Any]:
        """Check text going INTO a model (user prompt, retrieved document, tool result)
        for prompt injection, secrets and personal data. Returns action
        (allow|warn|redact|block), redacted text and findings."""
        return pipeline.check_input(text).to_dict()

    def scan_output(text: str) -> Dict[str, Any]:
        """Check text coming OUT of a model for leaked secrets, personal data and banned topics."""
        return pipeline.check_output(text).to_dict()

    def redact(text: str) -> Dict[str, Any]:
        """Redact personal data and secrets in text, regardless of the loaded policy."""
        return redactor.check_input(text).to_dict()

    def list_guards() -> Dict[str, Any]:
        """List the available guard types."""
        return {"guards": sorted(GUARDS)}

    return {"scan_input": scan_input, "scan_output": scan_output,
            "redact": redact, "list_guards": list_guards}


def create_server(pipeline: Optional[Pipeline] = None):
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise SystemExit('guardkit-mcp needs the MCP SDK: pip install "guardkit[mcp]"') from e
    server = FastMCP("guardkit")
    for name, fn in build_tools(pipeline or from_dict(DEFAULT_POLICY)).items():
        server.tool(name=name)(fn)
    return server


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardkit-mcp", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", help="YAML policy file (default: built-in policy)")
    a = ap.parse_args(argv)
    from .policy import load
    pipeline = load(a.policy) if a.policy else from_dict(DEFAULT_POLICY)
    create_server(pipeline).run()          # stdio transport
    return 0


if __name__ == "__main__":
    sys.exit(main())
