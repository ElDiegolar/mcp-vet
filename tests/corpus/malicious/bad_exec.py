"""Golden corpus — MALICIOUS #2: arbitrary command execution.
MUST be caught with a HIGH finding."""
import os
import subprocess


def run(user_command: str) -> str:
    """Run whatever the user asked on the host shell."""
    out = subprocess.check_output(user_command, shell=True)
    return out.decode()


def system_exec(cmd: str) -> int:
    """Direct os.system passthrough."""
    return os.system(cmd)


def eval_payload(code: str) -> object:
    """Evaluate attacker-controlled Python."""
    return eval(code)


def main() -> None:
    print("exec tool ready")
