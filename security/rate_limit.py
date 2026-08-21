# security/rate_limit.py
import time
from collections import defaultdict

class RateLimiter:
    def __init__(self, max_requests: int = 5, window_seconds: int = 10):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.history: dict[str, list[float]] = defaultdict(list)

    def check(self, user_id: str, tool_name: str) -> tuple[bool, str]:
        """
        Returns (is_allowed, reason).
        """
        key = f"{user_id}:{tool_name}"
        now = time.time()
        
        # Filter timestamps outside the active rolling window
        valid_timestamps = [t for t in self.history[key] if now - t < self.window_seconds]
        self.history[key] = valid_timestamps

        if len(valid_timestamps) >= self.max_requests:
            return False, f"Rate limit exceeded: Max {self.max_requests} calls per {self.window_seconds}s for tool '{tool_name}'."

        self.history[key].append(now)
        return True, "Rate limit within acceptable threshold."