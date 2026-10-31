import time
import random

def execute_with_retry(fn, max_retries=3, backoff_factor=1.5):
    attempt = 0
    while True:
        try:
            return fn()
        except Exception as err:
            attempt += 1
            if attempt > max_retries:
                raise err
            jitter = random.uniform(-0.1, 0.1)
            sleep_duration = max(0.1, (backoff_factor ** attempt) + jitter)
            time.sleep(sleep_duration)
