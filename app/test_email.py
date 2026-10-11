import sys
import os
import asyncio
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.scan_controller import run_email_scan

async def test():
    res = await run_email_scan("test@example.com")
    print(res.model_dump_json(indent=2))

if __name__ == "__main__":
    asyncio.run(test())
