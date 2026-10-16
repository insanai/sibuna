#!/usr/bin/env python3
"""Install, reinstall and remove the amd64 packages in disposable Debian, Fedora and Arch
containers, checking the account, the files, the seed helper and kept configuration."""
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
cases = [
    ('debian:13-slim', '*_amd64.deb',
     "sed -i '\\|path-exclude.*usr/share/doc|d' /etc/dpkg/dpkg.cfg.d/*; apt-get update -qq; "
     "apt-get install -y /packages/*_amd64.deb",
     'apt-get install -y --reinstall /packages/*_amd64.deb', 'apt-get remove -y sibuna'),
    # util-linux brings setpriv, which the minimal Fedora image lacks.
    ('fedora:44', '*.x86_64.rpm', 'dnf install -y util-linux /packages/*.x86_64.rpm',
     'rpm -Uvh --replacepkgs /packages/*.x86_64.rpm', 'rpm -e sibuna'),
    ('archlinux:base', '*.pkg.tar.zst',
     "sed -i 's#usr/share/doc/\\*##g' /etc/pacman.conf; pacman -Syu --noconfirm; "
     'pacman -U --noconfirm /packages/*.pkg.tar.zst',
     'pacman -U --noconfirm /packages/*.pkg.tar.zst', 'pacman -R --noconfirm sibuna-bin'),
]
# Runs the seed helper as the service user, as ExecStartPre does.
SEED = ('setpriv --reuid=sibuna --regid=sibuna --clear-groups '
        '/usr/lib/sibuna/seed.sh /var/lib/sibuna/admission.seed')
for image, pattern, install, reinstall, remove in cases:
    if len(list(root.glob(pattern))) != 1:
        raise SystemExit(f'check-linux-packages: expected one package matching {pattern}')
    # These images are installation fixtures, not bases of anything released.
    script = install + f'''
/usr/bin/sibuna --version
getent passwd sibuna
test -f /usr/lib/systemd/system/sibuna.service
test -f /usr/lib/sysusers.d/sibuna.conf
test -f /usr/share/doc/sibuna/SECURITY.md
test -f /usr/share/doc/sibuna/LICENSES/LGPL-3.0.txt
test -f /usr/share/doc/sibuna/LICENSES/THIRD-PARTY-RUST.txt
install -d -o sibuna -g sibuna -m 0700 /var/lib/sibuna
{SEED}
grep -Eqx '[0-9a-f]{{64}}' /var/lib/sibuna/admission.seed
sha256sum /var/lib/sibuna/admission.seed > /tmp/seed-check
{SEED}
sha256sum -c /tmp/seed-check
test "$(stat -c %a /var/lib/sibuna/admission.seed)" = 600
test "$(stat -c %U /var/lib/sibuna/admission.seed)" = sibuna
! test -e /etc/systemd/system/multi-user.target.wants/sibuna.service
echo '# operator settings' >> /etc/sibuna/service.env
{reinstall}
grep -q 'operator settings' /etc/sibuna/service.env
sha256sum -c /tmp/seed-check
{remove}
! test -e /usr/bin/sibuna
sha256sum -c /tmp/seed-check
getent passwd sibuna
grep -q 'operator settings' /etc/sibuna/service.env*
'''
    subprocess.run(['docker', 'run', '--rm', '-v', f'{root}:/packages:ro', image,
                    '/bin/sh', '-euxc', script], check=True)
print('check-linux-packages: deb, rpm and Arch install, seed, reinstall and removal passed')
