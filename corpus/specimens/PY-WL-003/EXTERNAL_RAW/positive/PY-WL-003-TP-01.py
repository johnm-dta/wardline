def dispatch(obj):
    if hasattr(obj, "process"):
        obj.process()
