"""enricher dependency topological sort over ``{node: [dependencies]}`` mappings."""


def sort_deps(graph):
    """Return nodes ordered so dependencies precede dependants."""
    done = []
    seen = set()

    def visit(node):
        if node in seen:
            return
        seen.add(node)
        for dep in graph.get(node, ()):
            visit(dep)
        done.append(node)

    for node in sorted(graph):
        visit(node)
    return done
