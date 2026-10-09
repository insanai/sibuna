#!/usr/bin/env python3
"""Install upstream packages in disposable Debian/Fedora/Arch containers."""
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
cases = [
    ('debian:13-slim', '*.deb', "sed -i '\\|path-exclude.*usr/share/doc|d' /etc/dpkg/dpkg.cfg.d/*; apt-get update -qq; apt-get install -y /packages/*.deb", 'apt-get install -y --reinstall /packages/*.deb', 'apt-get remove -y sibuna'),
    ('fedora:44', '*.rpm', 'dnf install -y /packages/*.rpm', 'rpm -Uvh --replacepkgs /packages/*.rpm', 'rpm -e sibuna'),
    ('archlinux:base', '*.pkg.tar.zst', 'pacman -Syu --noconfirm; pacman -U --noconfirm /packages/*.pkg.tar.zst', 'pacman -U --noconfirm /packages/*.pkg.tar.zst', 'pacman -R --noconfirm sibuna-bin'),
]
for image, pattern, command, reinstall, remove in cases:
    packages = list(root.glob(pattern))
    if len(packages) != 1:
        raise SystemExit(f'expected one amd64 package: {pattern}')
    # These are installation fixtures, not bases shipped in the release image.
    script = command + '''
/usr/bin/sibuna --version
getent passwd sibuna
test -f /usr/lib/systemd/system/sibuna.service
test -f /usr/lib/sysusers.d/sibuna.conf
test -f /usr/share/doc/sibuna/SECURITY.md
test -f /usr/share/doc/sibuna/LICENSES/AGPL-3.0.txt
install -d -o sibuna -g sibuna -m 0700 /var/lib/sibuna
python3 -c "import os,pwd; user=pwd.getpwnam('sibuna'); os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid); os.execv('/usr/lib/sibuna/seed.py', ['seed.py', '/var/lib/sibuna/admission.seed'])"
sha256sum /var/lib/sibuna/admission.seed > /tmp/seed-check
python3 -c "import os,pwd; user=pwd.getpwnam('sibuna'); os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid); os.execv('/usr/lib/sibuna/seed.py', ['seed.py', '/var/lib/sibuna/admission.seed'])"
sha256sum -c /tmp/seed-check
test "$(stat -c %a /var/lib/sibuna/admission.seed)" = 600
! test -e /etc/systemd/system/multi-user.target.wants/sibuna.service
'''
    script += "echo '# operator settings' >> /etc/sibuna/service.env\n" + reinstall + "\n"
    script += "grep -q 'operator settings' /etc/sibuna/service.env\nsha256sum -c /tmp/seed-check\n" + remove + "\n"
    script += "sha256sum -c /tmp/seed-check\ngetent passwd sibuna\ngrep -q 'operator settings' /etc/sibuna/service.env*\n"
    subprocess.run(['docker', 'run', '--rm', '--network', 'host', '-v', f'{root}:/packages:ro', image,
                    '/bin/sh', '-euxc', script], check=True)
print('deb/rpm/Arch installation and private persistent seed checks passed')
