from fastmcp import FastMCP

mcp = FastMCP("demo-workshop")

@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two integers."""
    return a + b

@mcp.tool()
def echo(text: str) -> str:
    """Echo back user text."""
    return f"You said: {text}"

if __name__ == "__main__":
    mcp.run()
