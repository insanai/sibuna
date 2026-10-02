"""Own a daemon process group so Windows CTRL_BREAK follows the native shutdown path."""
import os
import signal
import subprocess


def spawn(*args, **kwargs):
    if os.name == "nt":
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | subprocess.CREATE_NEW_PROCESS_GROUP
    return subprocess.Popen(*args, **kwargs)


def terminate(proc):
    if os.name == "nt":
        proc.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        proc.terminate()
