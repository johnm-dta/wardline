def route(event):
    match event:
        case {"type": "click", "x": x, "y": y}:
            handle_click(x, y)
        case {"type": "scroll"}:
            handle_scroll()
