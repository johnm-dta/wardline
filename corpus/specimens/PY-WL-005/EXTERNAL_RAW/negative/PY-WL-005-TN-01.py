import logging
log = logging.getLogger(__name__)

def process(data):
    try:
        x = int(data)
    except ValueError:
        log.error("Failed to parse: %s", data)
