def check_config(config):
    if "database" in config:
        connect(config["database"])
