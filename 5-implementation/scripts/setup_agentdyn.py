"""Explicit source download. The benchmark refuses an unpinned checkout."""
import subprocess
import sys

from app.evaluation.agentdyn import COMMIT, SOURCE
from app.settings import ROOT


def main():
    if not SOURCE.exists():
        subprocess.run(["git", "clone", "--filter=blob:none", "--no-checkout", "https://github.com/SaFo-Lab/AgentDyn.git", str(SOURCE)], check=True)
        subprocess.run(["git", "-C", str(SOURCE), "sparse-checkout", "set", "src/agentdojo"], check=True)
        subprocess.run(["git", "-C", str(SOURCE), "checkout", COMMIT], check=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "-e", str(ROOT) + "[agent_benchmark]"], check=True)
    print("Pinned AgentDyn source and benchmark dependencies installed.")


if __name__ == "__main__":
    main()
