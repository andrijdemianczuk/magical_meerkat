"""Client tests, including transport parity.

The parity test is the important one: a fixture scanned over real JSON-RPC must
produce exactly what the in-process path produces. If those ever diverge, the
corpus stops being evidence about real scans.
"""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel.attacks import for_class, registry
from sentinel.client import (
    HttpClient,
    InvocationNotPermitted,
    ProtocolError,
    StdioClient,
    TransportError,
)
from sentinel.testbed.evaluate import evaluate
from sentinel.testbed.loader import load_corpus
from sentinel.testbed.server import FixtureServer

CORPUS = load_corpus()


def server_command(fixture):
    return [sys.executable, "-m", "sentinel.testbed.server", str(fixture.source)]


@pytest.fixture(params=CORPUS, ids=lambda f: f.id)
def fixture(request):
    return request.param


# --- stdio ---------------------------------------------------------------


def test_initialize_reports_server_info(fixture):
    with StdioClient(server_command(fixture)) as client:
        assert fixture.id in client.server_info.name
        assert client.server_info.protocol_version == client.protocol_version


def test_list_tools_matches_the_fixture(fixture):
    with StdioClient(server_command(fixture)) as client:
        over_wire = {t.name: t for t in client.list_tools()}
    assert set(over_wire) == {t.name for t in fixture.tools}
    for declared in fixture.tools:
        assert over_wire[declared.name].description == declared.description
        assert over_wire[declared.name].input_schema == declared.input_schema


def test_passive_client_refuses_to_invoke_tools(fixture):
    """D-002 made structural: a passive scan cannot fire the target's tools."""
    with StdioClient(server_command(fixture)) as client:
        tool = client.list_tools()[0]
        with pytest.raises(InvocationNotPermitted):
            client.call_tool(tool.name)


def test_active_client_can_invoke_tools(fixture):
    with StdioClient(server_command(fixture), allow_invocation=True) as client:
        tool = client.list_tools()[0]
        assert "content" in client.call_tool(tool.name, {})


def test_listed_tools_carry_no_response_until_probed(fixture):
    with StdioClient(server_command(fixture), allow_invocation=True) as client:
        tool = client.list_tools()[0]
        assert tool.response_text == ""
        declared = next(t for t in fixture.tools if t.name == tool.name)
        assert client.probe(tool).response_text == declared.response_text


def test_scan_over_the_wire_matches_the_in_process_result(fixture):
    """Transport parity — the corpus must mean the same thing either way."""
    expected = evaluate(fixture)
    attacks = [a for a in for_class(fixture.attack_class) if a.mode == fixture.mode]
    if expected is None or not attacks:
        pytest.skip("no detector for this class")

    with StdioClient(server_command(fixture), allow_invocation=True) as client:
        tools = client.list_tools()
        if fixture.mode == "active":
            tools = [client.probe(t) for t in tools]
        detected = any(a.analyze(t).detected for a in attacks for t in tools)

    assert detected is expected.detected
    assert detected is fixture.expect_detect


def test_command_must_be_an_argument_vector():
    with pytest.raises(ValueError, match="argument vector"):
        StdioClient("python -m sentinel.testbed.server fixture.yaml")


def test_missing_executable_is_a_transport_error():
    with pytest.raises(TransportError, match="could not start"):
        StdioClient(["definitely-not-a-real-binary-xyz"])


def test_unresponsive_server_times_out_instead_of_hanging():
    client = StdioClient([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5)
    try:
        with pytest.raises(TransportError, match="no response within"):
            client.initialize()
    finally:
        client.close()


def test_server_that_exits_is_reported_with_its_stderr():
    script = "import sys; sys.stderr.write('boom'); sys.exit(3)"
    client = StdioClient([sys.executable, "-c", script])
    try:
        with pytest.raises(TransportError):
            client.initialize()
    finally:
        client.close()


def test_non_json_output_is_a_protocol_error():
    client = StdioClient([sys.executable, "-c", "print('not json'); import time; time.sleep(5)"])
    try:
        with pytest.raises(ProtocolError, match="invalid JSON"):
            client.initialize()
    finally:
        client.close()


# --- http ----------------------------------------------------------------


def make_http_server(fixture, *, sse=False):
    backend = FixtureServer(fixture)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            reply = backend.handle(json.loads(body))
            if reply is None:
                self.send_response(202)
                self.end_headers()
                return
            payload = json.dumps(reply).encode()
            self.send_response(200)
            if sse:
                self.send_header("Content-Type", "text/event-stream")
                payload = b"event: message\ndata: " + payload + b"\n\n"
            else:
                self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "test-session")
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.mark.parametrize("sse", [False, True], ids=["json", "sse"])
def test_http_client_scans_a_fixture(sse):
    poisoned = next(f for f in CORPUS if f.id == "tool-poisoning/exfil-ssh-key")
    httpd = make_http_server(poisoned, sse=sse)
    try:
        endpoint = f"http://127.0.0.1:{httpd.server_address[1]}/mcp"
        with HttpClient(endpoint) as client:
            assert client.session_id == "test-session"
            tools = client.list_tools()
        attack = registry()["tool_poisoning.description_instructions"]
        assert attack.analyze(tools[0]).detected
    finally:
        httpd.shutdown()


def test_http_endpoint_must_be_a_url():
    with pytest.raises(ValueError, match="http"):
        HttpClient("localhost:8080")


def test_unreachable_endpoint_is_a_transport_error():
    client = HttpClient("http://127.0.0.1:9/mcp", timeout=1.0)
    with pytest.raises(TransportError, match="could not reach"):
        client.initialize()


# --- server --------------------------------------------------------------


def test_notifications_get_no_reply():
    backend = FixtureServer(CORPUS[0])
    assert backend.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_unknown_method_returns_method_not_found():
    backend = FixtureServer(CORPUS[0])
    reply = backend.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/teleport"})
    assert reply["error"]["code"] == -32601


def test_calling_an_unknown_tool_returns_invalid_params():
    backend = FixtureServer(CORPUS[0])
    reply = backend.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "nope"}}
    )
    assert reply["error"]["code"] == -32602
