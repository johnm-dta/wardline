def run_tasks(tasks):
    try:
        async with asyncio.TaskGroup() as tg:
            for t in tasks:
                tg.create_task(t)
    except* BaseException as eg:
        log.error("task group failed: %s", eg)
