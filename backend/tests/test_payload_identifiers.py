from backend.app.enrichers.payload_identifiers import camel_case, snakeify


def test_converts_camel_to_snake():
    assert snakeify("parseHTTPResponse") in ("parse_http_response", "parse_httpresponse")


def test_converts_snake_to_camel():
    assert camel_case("parse_http_response") == "parseHttpResponse"
