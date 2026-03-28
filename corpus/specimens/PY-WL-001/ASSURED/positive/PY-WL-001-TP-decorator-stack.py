def deco1(f): return f
def deco2(f): return f
def deco3(f): return f

@deco1
@deco2
@deco3
def process(data):
    x = data.get("key", "default")
