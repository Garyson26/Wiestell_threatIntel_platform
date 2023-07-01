from backend.app.enrichers.pipeline_graph import resolve_order


def test_dependencies_come_first():
    order = resolve_order({"app": ["lib"], "lib": ["core"], "core": []})
    assert order.index("core") < order.index("lib") < order.index("app")


def test_handles_independent_nodes():
    assert sorted(resolve_order({"a": [], "b": []})) == ["a", "b"]
