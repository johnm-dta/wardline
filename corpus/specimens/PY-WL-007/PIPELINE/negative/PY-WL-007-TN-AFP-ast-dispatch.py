import ast

def extract_names(node):
    """isinstance on ast.Name is structural dispatch, not trust boundary check."""
    if isinstance(node, ast.Name):
        return [node.id]
    elif isinstance(node, ast.Attribute):
        return [node.attr]
    return []
