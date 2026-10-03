"""Own daemon shutdown signals without interrupting the Windows test runner's console."""
import os
import signal
import subprocess

if os.name == "nt":
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    handler_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
    kernel.AttachConsole.argtypes = [wintypes.DWORD]
    kernel.AttachConsole.restype = wintypes.BOOL
    kernel.FreeConsole.restype = wintypes.BOOL
    kernel.SetConsoleCtrlHandler.argtypes = [handler_type, wintypes.BOOL]
    kernel.SetConsoleCtrlHandler.restype = wintypes.BOOL
    kernel.GenerateConsoleCtrlEvent.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.GenerateConsoleCtrlEvent.restype = wintypes.BOOL

    @handler_type
    def ignore_break(event):
        return event == signal.CTRL_BREAK_EVENT


def spawn(*args, **kwargs):
    if os.name == "nt":
        # A private console scopes CTRL_BREAK even when a hosted runner's shared
        # console has unusual process-group behavior. Pipes remain caller-owned.
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | subprocess.CREATE_NEW_CONSOLE
        if "startupinfo" not in kwargs:
            info = subprocess.STARTUPINFO()
            info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            info.wShowWindow = subprocess.SW_HIDE
            kwargs["startupinfo"] = info
    proc = subprocess.Popen(*args, **kwargs)
    proc.sibuna_private_console = os.name == "nt"
    return proc


def terminate(proc):
    if os.name != "nt":
        return proc.terminate()
    if not getattr(proc, "sibuna_private_console", False):
        raise RuntimeError("Windows console shutdown requires process_control.spawn")
    kernel.FreeConsole()
    try:
        if not kernel.AttachConsole(proc.pid):
            if proc.poll() is not None:
                return
            raise ctypes.WinError(ctypes.get_last_error())
        # AttachConsole resets handlers. Install after attaching and keep the callback
        # alive at module scope until every possible control delivery has completed.
        if not kernel.SetConsoleCtrlHandler(ignore_break, True):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.GenerateConsoleCtrlEvent(signal.CTRL_BREAK_EVENT, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        proc.wait(timeout=10)
    finally:
        kernel.FreeConsole()
        kernel.AttachConsole(0xffffffff)  # Restore the parent's console when one exists.
