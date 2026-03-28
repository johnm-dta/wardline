import logging

logger = logging.getLogger(__name__)

def persist_record(store, record):
    """Logger.error in broad handler looks audit-shaped but logger is not an audit receiver."""
    try:
        store.write(record)
    except Exception:
        logger.error("audit record lost: %s", record.id)
