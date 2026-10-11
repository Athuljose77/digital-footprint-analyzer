import sys
import os
import asyncio

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.core.scan_controller import run_system_scan

async def test():
    res = await run_system_scan()
    print(res.model_dump_json())

if __name__ == "__main__":
    asyncio.run(test())
