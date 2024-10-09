from backend.app.utils.field_wordcase import camel_case, to_snake


def test_converts_camel_to_snake():
    assert to_snake("parseHTTPResponse") in ("parse_http_response", "parse_httpresponse")


def test_converts_snake_to_camel():
    assert camel_case("parse_http_response") == "parseHttpResponse"
