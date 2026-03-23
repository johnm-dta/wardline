def fetch(url):
    try:
        return request(url)
    except:
        return None
