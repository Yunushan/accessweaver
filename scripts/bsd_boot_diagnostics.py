"""Read-only, allowlisted boot observations from a stopped disposable BSD disk.

This helper never mounts, boots, repairs or writes the image and never returns
file contents, user data, keys, log lines or paths from inside the guest.
"""
import json
import os
from pathlib import Path
import re
import stat
import sys


def global_password_auth_disabled(data):
    # OpenSSH uses the first obtained global value. A Match-only or later
    # directive must not be reported as the effective global setting.
    for line in data.splitlines():
        fields = line.split(b"#", 1)[0].lower().split()
        if not fields:
            continue
        if fields[0] == b"match":
            break
        if fields[0] == b"passwordauthentication":
            return fields == [b"passwordauthentication", b"no"]
    return False


def boot_observations(read_file, exists, client_public, host_public):
    hostname = read_file('/etc/rc.conf.d/hostname')
    passwd = read_file('/etc/passwd')
    authorized = read_file('/home/awtest/.ssh/authorized_keys')
    host_key = read_file('/etc/ssh/ssh_host_ed25519_key.pub')
    sshd = read_file('/etc/ssh/sshd_config')
    lease = read_file('/var/db/dhclient.leases.vtnet0')
    nuage = read_file('/var/log/nuageinit.log')
    messages = read_file('/var/log/messages')
    return {
        'inspectionComplete': True,
        'hostnameConfigured': b'hostname="awbsd"' in hostname.splitlines(),
        'nuageCachePresent': exists('/var/cache/nuageinit/user_data'),
        'testUserCreated': bool(re.search(rb'^awtest:[^:\r\n]*:[1-9][0-9]*:', passwd, re.M)),
        'clientKeyInstalled': client_public.strip() in [line.strip() for line in authorized.splitlines()],
        'hostKeyInstalled': host_key.strip() == host_public.strip(),
        'passwordAuthenticationDisabled': global_password_auth_disabled(sshd),
        'sshdPIDFilePresent': exists('/var/run/sshd.pid'),
        'controlAddressDHCPLeasePresent': bool(re.search(rb'fixed-address\s+10\.0\.2\.15\s*;', lease)),
        'nuageLogPresent': exists('/var/log/nuageinit.log'),
        'nuageParseErrorObserved': b'error parsing' in nuage,
        'nuageArgumentErrorObserved': b'bad argument' in nuage,
        'nuageTracebackObserved': b'stack traceback' in nuage,
        'nuageOpenErrorObserved': b'unable to open' in nuage or b'Impossible to open' in nuage,
        'sshdMessageObserved': b'sshd[' in messages,
        'cloudProviderMissingObserved': b'Impossible to find a cloud init provider' in messages,
    }


def owned_regular(path):
    info = path.lstat()
    if (path.resolve() != path or not stat.S_ISREG(info.st_mode) or
            info.st_uid != os.geteuid() or info.st_nlink != 1):
        raise RuntimeError('unexpected private disk input')


def inspect(capsule):
    repo = Path(__file__).resolve().parents[1]
    root = repo / 'build' / 'bsd-capsules'
    if capsule.parent != root or capsule.resolve() != capsule:
        raise RuntimeError('unexpected private capsule path')
    for directory in (root, capsule):
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RuntimeError('unexpected private capsule owner or mode')
    for name in ('base.qcow2', 'overlay.qcow2', 'client.pub', 'host.pub'):
        owned_regular(capsule / name)
    # Imports are CI-only, hash-locked tools. Ordinary guard/unit tests do not
    # import them. No guest pathname is ever resolved against the host filesystem.
    from dissect.ffs.ffs import FFS
    from dissect.ffs.exceptions import FileNotFoundError as GuestFileNotFound
    from dissect.hypervisor.disk.qcow2 import QCow2
    from dissect.volume.disk.schemes.gpt import GPT

    with (capsule / 'base.qcow2').open('rb') as base, (capsule / 'overlay.qcow2').open('rb') as overlay:
        original = QCow2(base)
        if original.needs_backing_file or original.needs_data_file or not 0 < original.size <= 16 << 30:
            raise RuntimeError('unexpected base disk references')
        base.seek(0)
        disk = QCow2(overlay, backing_file=base)
        if (disk.needs_data_file or disk.auto_backing_file != str(capsule / 'base.qcow2') or
                disk.size != original.size):
            raise RuntimeError('unexpected overlay disk references')
        partitions = GPT(disk.open()).partitions
        candidates = [p for p in partitions if p.name == 'rootfs']
        if len(candidates) != 1:
            raise RuntimeError('unexpected root partition set')
        selected = candidates[0]
        if selected.offset < 0 or selected.size <= 0 or selected.offset + selected.size > disk.size:
            raise RuntimeError('unexpected root partition bounds')
        fs = FFS(selected.open())
        if fs.version != 2:
            raise RuntimeError('unexpected guest filesystem')

        def exists(name):
            try:
                fs.get(name)
                return True
            except GuestFileNotFound:
                return False

        def read_file(name):
            try:
                node = fs.get(name)
            except GuestFileNotFound:
                return b''
            if not stat.S_ISREG(node.mode) or node.size > 1 << 20:
                raise RuntimeError('boot observation file exceeds bounds or is not regular')
            with node.open() as stream:
                data = stream.read((1 << 20) + 1)
            if len(data) > 1 << 20:
                raise RuntimeError('boot observation read exceeds bounds')
            return data

        keys = []
        for name in ('client.pub', 'host.pub'):
            with (capsule / name).open('rb') as source:
                key = source.read(2049).strip()
            if len(key) > 2048 or not key.startswith(b'ssh-ed25519 '):
                raise RuntimeError('unexpected public fixture identity')
            keys.append(key)
        return boot_observations(read_file, exists, *keys)


def main():
    if (sys.platform != 'linux' or os.geteuid() == 0 or
            os.environ.get('GITHUB_ACTIONS') != 'true' or
            os.environ.get('RUNNER_ENVIRONMENT') != 'github-hosted' or
            os.environ.get('ACCESSWEAVER_DISPOSABLE_BSD_GUEST_TEST') != '1' or len(sys.argv) != 2):
        raise RuntimeError('hosted private postmortem context required')
    print(json.dumps(inspect(Path(sys.argv[1]))))


if __name__ == '__main__':
    main()
