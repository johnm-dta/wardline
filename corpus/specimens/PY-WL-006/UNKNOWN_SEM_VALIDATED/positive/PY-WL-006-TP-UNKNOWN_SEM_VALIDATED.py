def process():
    try:
        risky()
    except Exception as e:
        audit.save({"error": str(e)})
