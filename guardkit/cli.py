"""Command line: guardkit scan --policy policy.yaml --stage input [FILE|-]"""
import argparse
import json
import sys

from . import load


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardkit")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sc = sub.add_parser("scan", help="scan text against a policy")
    sc.add_argument("--policy", required=True)
    sc.add_argument("--stage", choices=["input", "output"], default="input")
    sc.add_argument("--no-text", action="store_true", help="omit the (redacted) text from the output")
    sc.add_argument("file", nargs="?", default="-")
    sv = sub.add_parser("serve", help="run the local HTTP service")
    sv.add_argument("--policy", required=True)
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8080)
    a = ap.parse_args(argv)
    if a.cmd == "serve":
        from .server import serve
        serve(load(a.policy), a.host, a.port)
        return 0
    text = sys.stdin.read() if a.file == "-" else open(a.file, encoding="utf-8").read()
    pipe = load(a.policy)
    res = (pipe.check_input if a.stage == "input" else pipe.check_output)(text)
    print(json.dumps(res.to_dict(include_text=not a.no_text), indent=2))
    return 1 if res.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
