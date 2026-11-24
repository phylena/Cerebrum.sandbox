"""Run the service: API + job runners + maintenance loop (+ egress proxy if enabled)."""
import logging
import os

import uvicorn

from .api.app import create_app

if __name__ == "__main__":
    logging.basicConfig(level=os.environ.get("SANDBOX_LOG_LEVEL", "INFO"), format="%(message)s")
    app = create_app()
    app.state.jobs.start()
    app.state.maintenance.start()
    uvicorn.run(app, host=os.environ.get("SANDBOX_HOST", "127.0.0.1"),
                port=int(os.environ.get("SANDBOX_PORT", "8300")), access_log=False)
