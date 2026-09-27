from mitmproxy_mcp.core.recorder import SimpleRequest, TrafficDB


def test_generate_curl_quotes_malicious_method():
    db = TrafficDB()
    req = SimpleRequest(
        method="GET; rm -rf /",
        url="https://example.com/api",
        headers={"Authorization": "Bearer token"},
        body="test body",
    )
    curl_cmd = db._generate_curl(req)
    assert "'GET; rm -rf /'" in curl_cmd
