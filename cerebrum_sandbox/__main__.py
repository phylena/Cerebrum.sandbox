import os

import uvicorn

from .api.app import create_app

if __name__ == "__main__":
    uvicorn.run(create_app(), host=os.environ.get("SANDBOX_HOST", "127.0.0.1"),
                port=int(os.environ.get("SANDBOX_PORT", "8300")))
