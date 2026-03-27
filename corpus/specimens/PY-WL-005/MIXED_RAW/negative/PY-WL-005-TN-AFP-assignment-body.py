def cleanup(resource):
    """Looks silent but body is an assignment, not pass or ellipsis."""
    try:
        resource.release()
    except Exception:
        resource.state = "abandoned"
