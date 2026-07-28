"""Command line interface.

    sentinel scan https://host/mcp
    sentinel scan --stdio -- python -m sentinel.testbed.server fixture.yaml
    sentinel baseline https://host/mcp --output approved.json
    sentinel corpus

Passive is the default everywhere. `--active` invokes the target's tools, which
means a tool called `send_email` sends one, and against a non-loopback host it
additionally requires `--authorized` — an assertion by the operator that they
have permission to attack that server. That gate is deliberately not
satisfiable by a config file or an allowlist; running a corpus of attacks
against someone else's endpoint should take a conscious act.

Exit codes: 0 nothing fired, 1 findings, 2 could not scan.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

from sentinel import __version__
from sentinel import baseline as bl
from sentinel.client import HttpClient, StdioClient
from sentinel.client.base import BaseClient, MCPError
from sentinel.report import render
from sentinel.scan import scan
from sentinel.testbed import evaluate

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def is_loopback(target: str) -> bool:
    """Whether a URL points at this machine."""
    host = urlparse(target).hostname or ""
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def open_client(args: argparse.Namespace, *, allow_invocation: bool = False) -> BaseClient:
    if args.stdio:
        if not args.target:
            raise ValueError("--stdio needs a command, e.g. --stdio -- python -m server")
        return StdioClient(
            args.target, allow_invocation=allow_invocation, timeout=args.timeout
        )
    if len(args.target) != 1:
        raise ValueError("expected exactly one endpoint URL (use --stdio for a local command)")
    return HttpClient(args.target[0], allow_invocation=allow_invocation, timeout=args.timeout)


def describe_target(args: argparse.Namespace) -> str:
    return "stdio://" + " ".join(args.target) if args.stdio else args.target[0]


def _check_authorization(args: argparse.Namespace) -> str | None:
    """Refuse an active scan of a remote host without an explicit assertion."""
    if not getattr(args, "active", False) or args.stdio:
        return None
    if is_loopback(args.target[0]) or args.authorized:
        return None
    return (
        f"refusing to actively scan {args.target[0]}\n"
        "  --active invokes the target's tools, which has real side effects.\n"
        "  Against a host that is not loopback this requires --authorized,\n"
        "  asserting you have permission to attack that server."
    )


def cmd_scan(args: argparse.Namespace) -> int:
    if problem := _check_authorization(args):
        print(problem, file=sys.stderr)
        return EXIT_ERROR

    snapshot = None
    if args.baseline:
        snapshot = bl.load(Path(args.baseline))

    client = open_client(args, allow_invocation=args.active)
    try:
        result = scan(
            client,
            scanned_at=datetime.now(UTC).isoformat(timespec="seconds"),
            endpoint=describe_target(args),
            active=args.active,
            baseline=snapshot,
        )
    finally:
        client.close()

    print(render(result))
    return EXIT_FINDINGS if result.detected else EXIT_OK


def cmd_baseline(args: argparse.Namespace) -> int:
    client = open_client(args)
    try:
        server = client.initialize()
        tools = client.list_tools()
    finally:
        client.close()

    snapshot = bl.capture(
        tools,
        endpoint=describe_target(args),
        captured_at=datetime.now(UTC).isoformat(timespec="seconds"),
        protocol_version=server.protocol_version,
    )
    destination = Path(args.output)
    bl.save(snapshot, destination)
    print(f"Approved {len(tools)} tool(s) from {snapshot.endpoint}")
    print(f"Baseline written to {destination}")
    print("Review this file before trusting it — it records what was served, not what is safe.")
    return EXIT_OK


def cmd_corpus(args: argparse.Namespace) -> int:
    return evaluate.run(Path(args.corpus) if args.corpus else None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="MCP governance and red-team harness.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subcommands = parser.add_subparsers(dest="command", required=True)

    def add_target(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "target",
            nargs=argparse.REMAINDER,
            help="endpoint URL, or the command to run after --stdio",
        )
        sub.add_argument(
            "--stdio", action="store_true", help="target is a local command, not a URL"
        )
        sub.add_argument("--timeout", type=float, default=30.0, help="per-request timeout (s)")

    scan_parser = subcommands.add_parser("scan", help="scan a target for known attack classes")
    add_target(scan_parser)
    scan_parser.add_argument(
        "--active",
        action="store_true",
        help="invoke the target's tools (side effects) to reach active checks",
    )
    scan_parser.add_argument(
        "--authorized",
        action="store_true",
        help="assert you have permission to actively scan a non-loopback host",
    )
    scan_parser.add_argument("--baseline", help="approved-surface snapshot for change detection")
    scan_parser.set_defaults(handler=cmd_scan)

    baseline_parser = subcommands.add_parser(
        "baseline", help="record a target's current surface as approved"
    )
    add_target(baseline_parser)
    baseline_parser.add_argument(
        "--output", "-o", required=True, help="where to write the snapshot"
    )
    baseline_parser.set_defaults(handler=cmd_baseline)

    corpus_parser = subcommands.add_parser(
        "corpus", help="evaluate the detectors against the labelled fixture corpus"
    )
    corpus_parser.add_argument("--corpus", help="fixture directory (defaults to the bundled one)")
    corpus_parser.set_defaults(handler=cmd_corpus)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # argparse.REMAINDER keeps a leading "--" separator; drop it.
    if getattr(args, "target", None) and args.target[0] == "--":
        args.target = args.target[1:]
    try:
        return args.handler(args)
    except (MCPError, bl.BaselineError, ValueError, OSError) as exc:
        print(f"sentinel: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
