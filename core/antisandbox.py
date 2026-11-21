"""
antisandbox.py - best-effort detection of "this looks like an
automated analysis sandbox/VM, not a real end-user device", refusing
to run if enough independent signals agree.

IMPORTANT - what this does NOT do:
  This does NOT detect or stop an AI (or a human) reading the script's
  TEXT/bytecode statically without ever executing it. There is no
  runtime signal to check in that case - the code simply never runs,
  so none of the checks below ever fire. Anti-sandbox checks are only
  relevant to the "script gets handed to an automated dynamic-analysis
  environment (a malware sandbox, a CI runner used to auto-detonate
  suspicious files, etc.) that actually EXECUTES it" scenario - a
  narrower thing than "prevent any analysis of this file", which
  isn't something any runtime check can do.

Why multiple weighted signals instead of one hard check: every
individual signal below ALSO occurs on plenty of real, legitimate
end-user machines - a cheap VPS really can have 1 CPU core and 1GB
RAM; a freshly-reimaged laptop really can have low uptime; a real
physical machine can still get a VM-range MAC if using certain
virtual NICs/bridges for legitimate reasons. Refusing to run on any
ONE of these alone would false-positive constantly on real users.
Instead, each signal contributes a small weighted score, and only a
HIGH COMBINED score (several signals agreeing at once - the actual
pattern a real sandbox/VM shows, not just one coincidental match)
triggers a refusal. This is inherently a heuristic tuned to reduce
(not eliminate) false positives, never a guarantee.

Checks (Linux/Termux only - see module docstring notes per-check):
  - CPU core count suspiciously low (sandboxes are commonly given 1-2)
  - Total RAM suspiciously low (sandboxes commonly given <=2GB)
  - System uptime suspiciously short (a freshly-booted analysis VM)
  - Root filesystem size suspiciously small (sandbox disk images are
    often minimal, well under what a real installed OS accumulates)
  - MAC address matches a well-known virtualization vendor OUI prefix
    (VirtualBox, VMware, QEMU/KVM, Xen, Hyper-V, Parallels)
  - Hostname matches a generic/default pattern common in sandbox
    images (sandbox, test, vm, analysis, malware, cuckoo, etc.)
  - Known sandbox/VM-guest-tools artifact files present (VirtualBox
    Guest Additions, VMware tools, QEMU guest agent markers)

KNOWN LIMITATIONS (stated plainly):
  - Every check here is Linux/Termux-specific (reads /proc, /sys,
    hostname) - on any other OS, that check silently contributes 0
    and is skipped, never raises an error.
  - This is fundamentally a heuristic. A well-resourced sandbox that
    deliberately pads out CPU/RAM/uptime/disk to look like a real
    machine, and runs on bare-metal-passthrough virtualization with a
    spoofed MAC, defeats every single one of these signals - this
    raises the bar for casual/default sandbox configurations, it does
    not stop a determined, well-resourced analysis setup.
  - Termux on Android: uptime/CPU-count/RAM checks work as normal
    (they read the same /proc interfaces), but MAC address and
    hostname checks are less meaningful there (mobile devices don't
    look like VM vendor hardware in the first place, and Termux's
    hostname is usually whatever the phone itself is set to) - both
    checks naturally contribute close to 0 on a real phone, which is
    the correct (non-triggering) outcome, just noted here so it's
    understood why those two specifically won't ever fire on mobile.
"""
import os
import random
import string


def _rand_name(used: set, n: int = 9) -> str:
    while True:
        cand = "_" + "".join(random.choices(string.ascii_lowercase, k=n))
        if cand not in used:
            used.add(cand)
            return cand


def get_antisandbox_source(enabled: bool = False, score_threshold: int = 6) -> str:
    """
    enabled: off by default - see module docstring's false-positive
             discussion. Only turn this on for builds specifically
             targeting distribution scenarios where automated sandbox
             detonation is a real, specific concern, not as a default
             blanket protection - the false-positive risk to real
             users on modest/cheap hardware is genuine.
    score_threshold: minimum combined weighted score (see the per-check
             weights in the generated source) needed to refuse to run.
             Higher = fewer false positives but also easier for a
             sandbox to slip under the threshold; lower = the reverse.
             Default 6 requires roughly 3-4 independent signals to
             agree simultaneously, not just one or two.
    """
    if not enabled:
        return ""

    used = set()
    names = {k: _rand_name(used) for k in (
        "die", "score", "check_cpu", "check_ram", "check_uptime",
        "check_disk", "check_mac", "check_hostname", "check_artifacts",
        "runall",
    )}

    template = '''
import os

def {die}():
    try:
        os._exit(1)
    except Exception:
        raise SystemExit(1)

def {check_cpu}():
    try:
        n = os.cpu_count() or 0
        if n <= 1:
            return 3
        if n == 2:
            return 1
    except Exception:
        pass
    return 0

def {check_ram}():
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    mb = kb / 1024
                    if mb <= 1024:
                        return 3
                    if mb <= 2048:
                        return 1
                    break
    except Exception:
        pass
    return 0

def {check_uptime}():
    try:
        with open("/proc/uptime", "r") as f:
            seconds = float(f.read().split()[0])
            if seconds < 120:
                return 2
    except Exception:
        pass
    return 0

def {check_disk}():
    try:
        st = os.statvfs("/")
        total_gb = (st.f_blocks * st.f_frsize) / (1024 ** 3)
        if total_gb <= 12:
            return 2
        if total_gb <= 25:
            return 1
    except Exception:
        pass
    return 0

def {check_mac}():
    # Well-known OUI (first 3 octets) prefixes used by major
    # virtualization vendors' virtual NICs.
    _vm_ouis = (
        "00:05:69", "00:0c:29", "00:1c:14", "00:50:56",  # VMware
        "08:00:27", "0a:00:27",                          # VirtualBox
        "52:54:00",                                       # QEMU/KVM libvirt default
        "00:16:3e",                                       # Xen
        "00:15:5d",                                       # Hyper-V
        "00:1c:42",                                       # Parallels
    )
    try:
        base = "/sys/class/net"
        if not os.path.isdir(base):
            return 0
        for iface in os.listdir(base):
            if iface == "lo":
                continue
            addr_path = os.path.join(base, iface, "address")
            try:
                with open(addr_path, "r") as f:
                    mac = f.read().strip().lower()
                if mac in ("00:00:00:00:00:00", ""):
                    continue
                for oui in _vm_ouis:
                    if mac.startswith(oui):
                        return 3
                # Locally-administered bit set (2nd hex digit is 2/6/a/e)
                # is common for VM/container virtual NICs in general,
                # even ones not matching a specific vendor OUI above -
                # weighted lower since plenty of legitimate virtual/
                # bridged interfaces on real hardware also set this.
                if len(mac) >= 2 and mac[1] in ("2", "6", "a", "e"):
                    return 1
            except Exception:
                continue
    except Exception:
        pass
    return 0

def {check_hostname}():
    _suspicious = (
        "sandbox", "malware", "cuckoo", "analysis", "sample",
        "test-vm", "testvm", "virus", "vmware", "virtualbox",
    )
    try:
        import socket as _vhsocket2
        h = _vhsocket2.gethostname().lower()
        for s in _suspicious:
            if s in h:
                return 2
        if h in ("vm", "vagrant", "docker", "container"):
            return 1
    except Exception:
        pass
    return 0

def {check_artifacts}():
    _paths = (
        "/usr/lib/virtualbox", "/opt/VBoxGuestAdditions",
        "/usr/lib/vmware-tools", "/etc/vmware-tools",
        "/dev/vboxguest", "/dev/vboxuser",
        "/usr/bin/qemu-ga",
    )
    for p in _paths:
        if os.path.exists(p):
            return 2
    return 0

def {runall}():
    {score} = 0
    {score} += {check_cpu}()
    {score} += {check_ram}()
    {score} += {check_uptime}()
    {score} += {check_disk}()
    {score} += {check_mac}()
    {score} += {check_hostname}()
    {score} += {check_artifacts}()
    if {score} >= {threshold}:
        {die}()

{runall}()
'''
    return template.format(
        die=names["die"], score=names["score"], check_cpu=names["check_cpu"],
        check_ram=names["check_ram"], check_uptime=names["check_uptime"],
        check_disk=names["check_disk"], check_mac=names["check_mac"],
        check_hostname=names["check_hostname"], check_artifacts=names["check_artifacts"],
        runall=names["runall"], threshold=score_threshold,
    )
