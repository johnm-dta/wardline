def get_handler(module):
    handler = getattr(module, "on_event", None)
    if handler:
        handler()
