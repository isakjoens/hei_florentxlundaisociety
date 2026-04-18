#!/usr/bin/env python3
"""Start both backend and frontend servers."""

import subprocess
import sys
import os
import signal
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT, "backend")
FRONTEND_DIR = os.path.join(ROOT, "frontend")
VENV_PYTHON = os.path.join(BACKEND_DIR, "venv", "bin", "python")

procs: list[subprocess.Popen] = []


def cleanup(*_):
    for p in procs:
        try:
            p.terminate()
        except OSError:
            pass
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    sys.exit(0)


signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def free_port(port: int):
    """Kill any process occupying the given port."""
    try:
        result = subprocess.run(
            ["lsof", "-ti", f":{port}"], capture_output=True, text=True
        )
        pids = result.stdout.strip().split()
        for pid in pids:
            if pid:
                print(f"[run.py] Killing stale process {pid} on port {port}")
                os.kill(int(pid), signal.SIGKILL)
        if pids and pids[0]:
            time.sleep(0.5)
    except Exception:
        pass


def main():
    # Install frontend deps if needed
    if not os.path.isdir(os.path.join(FRONTEND_DIR, "node_modules")):
        print("[run.py] Installing frontend dependencies...")
        subprocess.run(["npm", "install"], cwd=FRONTEND_DIR, check=True)

    # Install backend deps if needed
    if not os.path.isdir(os.path.join(BACKEND_DIR, "venv")):
        print("[run.py] Creating backend venv...")
        subprocess.run([sys.executable, "-m", "venv", "venv"], cwd=BACKEND_DIR, check=True)
        subprocess.run([VENV_PYTHON, "-m", "pip", "install", "-r", "requirements.txt"],
                       cwd=BACKEND_DIR, check=True)

    # Free ports in case of stale processes
    free_port(8000)
    free_port(3000)

    print("[run.py] Starting backend on http://localhost:8000")
    backend = subprocess.Popen(
        [VENV_PYTHON, "-m", "uvicorn", "main:app", "--reload", "--port", "8000"],
        cwd=BACKEND_DIR,
    )
    procs.append(backend)

    print("[run.py] Starting frontend on http://localhost:3000")
    frontend = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=FRONTEND_DIR,
    )
    procs.append(frontend)

    print("[run.py] Both servers running. Press Ctrl+C to stop.")

    while True:
        for p in procs:
            if p.poll() is not None:
                print(f"[run.py] Process {p.args} exited with code {p.returncode}")
                cleanup()
        time.sleep(1)


if __name__ == "__main__":
    main()
