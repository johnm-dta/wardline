def load_plugin(name):
    try:
        import_module(name)
    except ImportError:
        ...
