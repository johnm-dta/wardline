def process_batch(items):
    for item in items:
        try:
            handle(item)
        except* ValueError:
            continue
