import os
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from dashboard import DashboardHandler


class handler(DashboardHandler):
    """Dedicated Vercel serverless entrypoint for /api/health so /api/health always returns JSON."""

    def do_GET(self) -> None:
        self.path = "/api/health"
        super().do_GET()
