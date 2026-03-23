def try_connect(host):
    try:
        connect(host)
    except ConnectionError:
        pass
