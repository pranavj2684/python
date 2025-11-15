import asyncio
from fastmcp import Client

async def main():
    async with Client("simple_server.py") as client:
        tools = await client.list_tools()
        print("Tools:", [t.name for t in tools])

        r = await client.call_tool("add", {"a": 4, "b": 9})
        print("Add result:", r.content[0].text)

        e = await client.call_tool("echo", {"text": "PyCon Ireland!"})
        print("Echo:", e.content[0].text)

asyncio.run(main())
