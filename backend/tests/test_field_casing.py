from scripts.field_casing import to_camel, to_snake


def test_converts_camel_to_snake():
    assert to_snake("parseHTTPResponse") in ("parse_http_response", "parse_httpresponse")


def test_converts_snake_to_camel():
    assert to_camel("parse_http_response") == "parseHttpResponse"
