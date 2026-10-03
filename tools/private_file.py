"""Set credential permissions using the platform's actual access-control mechanism."""
import os
from pathlib import Path
import subprocess


def permissions(path, private=True):
    path = Path(path)
    if os.name != "nt":
        path.chmod(0o600 if private else 0o644)
        return
    # User SIDs avoid localized account and group names. No administrator rights are needed.
    import csv
    identity = next(csv.reader(subprocess.check_output(
        ["whoami", "/user", "/fo", "csv", "/nh"], text=True).splitlines()))[1]
    # Elevated Windows accounts can create files owned by Administrators. Granting
    # the account alone is not an owner-only ACL until ownership is set explicitly.
    subprocess.run(["icacls", str(path), "/setowner", f"*{identity}"],
                   check=True, capture_output=True)
    args = ["icacls", str(path), "/inheritance:r", "/grant:r", f"*{identity}:(F)"]
    if private:
        args += ["/remove:g", "*S-1-1-0"]
    else:
        args += ["/grant:r", "*S-1-1-0:(R)"]
    subprocess.run(args, check=True, capture_output=True)
