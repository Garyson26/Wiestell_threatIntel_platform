"""enricher dependency topological sort over ``{node: [dependencies]}`` mappings."""


def sort_deps(graph):
    """Return nodes ordered so dependencies precede dependants."""
    done = []
    seen = set()
    stack = set()

    def visit(node):
        if node in stack:
            raise ValueError("cycle through %r" % node)
        if node in seen:
            return
        seen.add(node)
        stack.add(node)
        for dep in graph.get(node, ()):
            visit(dep)
        stack.discard(node)
        done.append(node)

    for node in sorted(graph):
        visit(node)
    return done


def first_cycle(graph):
    """Return one cycle as a node list, or None if the graph is acyclic."""
    path, on_path = [], set()

    def walk(node):
        if node in on_path:
            return path[path.index(node):] + [node]
        if node not in graph:
            return None
        path.append(node)
        on_path.add(node)
        for dep in graph.get(node, ()):
            found = walk(dep)
            if found:
                return found
        path.pop()
        on_path.discard(node)
        return None

    for node in sorted(graph):
        found = walk(node)
        if found:
            return found
    return None
