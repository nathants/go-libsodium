#!/usr/bin/env python3
"""Exercise the real caller's secret command, signals, and controlling terminal.
Only synthetic keys are used. Every process belongs to this private test fixture.
"""
import os
import pathlib
import pty
import signal
import subprocess
import sys
import tempfile
import time


def wait_until(probe):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("timed out waiting for subprocess evidence")


def read_pid(path):
    try:
        return int(path.read_text())
    except (FileNotFoundError, ValueError):
        return None


def exited(pid):
    result = os.waitpid(pid, os.WNOHANG)
    return result if result[0] else None


def stopped(pid):
    try:
        state = pathlib.Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[0]
        return state == "Z"
    except FileNotFoundError:
        return True


def kill_group(pid):
    if pid:
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


command = sys.argv[1:]
assert command, "caller executable required"
with tempfile.TemporaryDirectory(prefix="secret-command-test-") as directory:
    root = pathlib.Path(directory)
    loader = root / "loader"
    leader_file, child_file, done = root / "leader", root / "child", root / "done"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_REMOTE_AWS_SECRETKEY")}
    env["GIT_REMOTE_AWS_SECRETKEY_CMD"] = str(loader)
    for scenario in ("SIGINT", "SIGTERM", "tty", "tty-SIGTERM", "tty-interrupt", "exec-failure", "background"):
        for path in (leader_file, child_file, done):
            path.unlink(missing_ok=True)
        prompting = scenario in ("tty", "tty-interrupt", "tty-SIGTERM", "background")
        script = f"#!/bin/sh\necho $$ > '{leader_file}'\n"
        if prompting:
            script += f"sleep 60 &\necho $! > '{child_file}'\nread value </dev/tty\necho done > '{done}'\n"
            script += "printf '%s\\n' '" + "03" * 32 + "'\n"
        else:
            script += f"sleep 60 &\necho $! > '{child_file}'\nwait\n"
        loader.write_text(script)
        loader.chmod(0o700)
        if scenario == "exec-failure":
            loader.unlink()
        terminal = scenario not in ("SIGINT", "SIGTERM")
        master = None
        proc = None
        supervisor = None
        leader = None
        caller = None
        supervisor_group = None
        try:
            if terminal:
                # The supervisor remains the session/foreground group leader so
                # we can test restoration after the actual caller exits.
                supervisor, master = pty.fork()
                if supervisor == 0:
                    try:
                        before = os.tcgetpgrp(0)
                        kwargs = {"preexec_fn": os.setpgrp} if scenario == "background" else {}
                        caller = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)
                        (root / "caller").write_text(str(caller.pid))
                        caller.wait(timeout=8)
                        assert os.tcgetpgrp(0) == before, "terminal foreground group was not restored"
                        os._exit(0)
                    except BaseException:
                        os._exit(1)
                supervisor_group = supervisor
                caller = wait_until(lambda: read_pid(root / "caller"))
            else:
                proc = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
                caller = proc.pid
            if scenario not in ("exec-failure", "background"):
                leader = wait_until(lambda: read_pid(leader_file))
                child = wait_until(lambda: read_pid(child_file))
                if scenario in ("SIGINT", "SIGTERM", "tty-SIGTERM"):
                    os.kill(caller, signal.SIGINT if scenario == "SIGINT" else signal.SIGTERM)
                elif scenario == "tty-interrupt":
                    wait_until(lambda: os.tcgetpgrp(master) == leader)
                    os.write(master, b"\x03")
                else:
                    os.write(master, b"continue\n")
                    wait_until(done.exists)
            if proc:
                proc.wait(timeout=8)
            else:
                result = wait_until(lambda: exited(supervisor))
                supervisor = None
                assert os.waitstatus_to_exitcode(result[1]) == 0, "caller hung or failed to restore terminal"
            if scenario == "background":
                assert not leader_file.exists(), "background caller launched a potentially terminal-reading command"
            if leader:
                wait_until(lambda: stopped(leader) and stopped(child))
        finally:
            kill_group(leader or read_pid(leader_file))
            if proc and proc.poll() is None:
                kill_group(proc.pid)
                proc.wait()
            kill_group(supervisor_group)
            if scenario == "background":
                kill_group(caller)
            if supervisor:
                os.waitpid(supervisor, 0)
            if master is not None:
                os.close(master)
            (root / "caller").unlink(missing_ok=True)
        print(scenario + ": passed")
