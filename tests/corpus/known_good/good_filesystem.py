"""Golden corpus — known-good: a minimal filesystem-style MCP tool.
MUST scan with no HIGH findings."""
from typing import Optional


def read_file(path: str) -> Optional[str]:
    """Read a text file. Literal, local-only, no network."""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path: str, content: str) -> int:
    """Write a text file at the given path."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return len(content)


def list_dir(path: str) -> list:
    """List directory entries."""
    import os
    return os.listdir(path)


def main() -> None:
    print("filesystem tool ready")
