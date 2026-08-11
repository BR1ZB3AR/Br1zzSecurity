"""Behavioural and structural heuristics.

This layer catches what exact hashes cannot: samples never seen before. It never
issues a binary verdict on its own - each check contributes a weighted score and
the scanner decides, so a single weak signal is not enough to condemn a file.

Two deliberate false-positive controls:
  * Text/script pattern rules only run against files that actually look like
    scripts or text. Grepping arbitrary binaries for "curl | sh" is noise.
  * Structural checks (entropy, packers) only run against real ELF objects, so
    compressed archives and media are not flagged for being compressed.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from pathlib import Path

from .verdict import Detection, Severity

ENTROPY_SAMPLE = 256 * 1024
TEXT_PROBE = 8192

SCRIPT_EXTENSIONS = frozenset({
    ".sh", ".bash", ".zsh", ".ksh", ".csh", ".py", ".pl", ".rb", ".php",
    ".js", ".lua", ".ps1", ".r", ".tcl", ".awk", ".desktop", ".service",
})

DOCUMENT_EXTENSIONS = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".mp3", ".mp4", ".avi", ".csv",
})

EXECUTABLE_EXTENSIONS = frozenset({".sh", ".bash", ".elf", ".bin", ".run", ".exe", ".com", ".scr", ".py", ".pl"})

# ---------------------------------------------------------------------------
# Text pattern rules: (id, name, severity, pattern, description)
# ---------------------------------------------------------------------------

TEXT_RULES: list[tuple[str, str, Severity, re.Pattern[bytes], str]] = [
    (
        "H001", "HEUR:ReverseShell.DevTcp", Severity.CRITICAL,
        re.compile(rb"(?:bash|sh|zsh)\s+-[a-z]*i[a-z]*\s*>\s*&\s*/dev/(?:tcp|udp)/", re.I),
        "Interactive shell redirected to a network socket - a reverse shell.",
    ),
    (
        "H002", "HEUR:ReverseShell.Netcat", Severity.HIGH,
        re.compile(rb"\bn(?:c|cat|etcat)(?:\.\w+)?\s+(?:-[a-z]*\s+)*-[a-z]*e[a-z]*\s+/bin/(?:sh|bash)", re.I),
        "Netcat invoked with -e to execute a shell on connect.",
    ),
    (
        "H003", "HEUR:ReverseShell.Fifo", Severity.HIGH,
        re.compile(rb"mkfifo\s+[^;|&\n]{1,64}[;\n].{0,120}?\bnc\b", re.I | re.S),
        "Named pipe paired with netcat - a classic reverse-shell construction.",
    ),
    (
        "H004", "HEUR:ReverseShell.Python", Severity.CRITICAL,
        re.compile(rb"socket\.socket\(.{0,200}?(?:dup2|subprocess\.(?:call|Popen))", re.I | re.S),
        "Python socket wired directly to a subprocess or duplicated onto stdio.",
    ),
    (
        "H005", "HEUR:Dropper.CurlPipeShell", Severity.HIGH,
        re.compile(rb"(?:curl|wget)\s+[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b", re.I),
        "Remote content piped straight into a shell interpreter.",
    ),
    (
        "H006", "HEUR:Dropper.DownloadChmodExec", Severity.HIGH,
        re.compile(rb"(?:curl|wget)\s+[^\n]{0,200}(?:-O|-o|--output)[^\n]{0,120}[;&\n].{0,200}?chmod\s+[+0-7]*x", re.I | re.S),
        "Downloads a file, makes it executable, and runs it.",
    ),
    (
        "H007", "HEUR:Obfuscation.Base64Exec", Severity.HIGH,
        re.compile(rb"base64\s+(?:-{1,2}\w+\s+)*-{1,2}[dD]\w*\b[^\n]{0,80}\|\s*(?:ba|z)?sh\b", re.I),
        "Base64-decoded payload piped into a shell.",
    ),
    (
        "H008", "HEUR:Obfuscation.EvalDecode", Severity.HIGH,
        re.compile(rb"(?:eval|exec)\s*\(\s*(?:base64_decode|atob|__import__\s*\(\s*['\"]base64|gzinflate|str_rot13)", re.I),
        "Decoded data passed straight to eval/exec - hallmark of a packed script.",
    ),
    (
        "H009", "HEUR:Obfuscation.HexPipeShell", Severity.HIGH,
        re.compile(rb"(?:xxd\s+-r\s+-p|printf\s+['\"](?:\\\\x[0-9a-f]{2}){4,})[^\n]{0,80}\|\s*(?:ba|z)?sh\b", re.I),
        "Hex-encoded payload decoded and executed.",
    ),
    (
        "H010", "HEUR:Persistence.Cron", Severity.MEDIUM,
        # Requires an install action. Merely naming a cron path is what every
        # cron-management script and config file on the system does.
        re.compile(rb"(?:\|\s*crontab\s+-|crontab\s+-\s*$|(?:>>?|tee)\s*[^\n]{0,40}/(?:etc/cron\.[a-z]+|var/spool/cron))", re.I | re.M),
        "Installs a cron job for persistence.",
    ),
    (
        "H011", "HEUR:Persistence.ShellProfile", Severity.MEDIUM,
        re.compile(rb">>\s*(?:~|\$HOME|/home/[^/\s]+)/\.(?:bashrc|bash_profile|profile|zshrc|zprofile)", re.I),
        "Appends to a shell startup file to survive logout.",
    ),
    (
        "H012", "HEUR:Persistence.Autostart", Severity.MEDIUM,
        # Writing a unit or autostart file, not referencing one. `systemctl
        # enable` on its own is ordinary system administration.
        re.compile(rb"(?:(?:>>?|tee|cp\s+|mv\s+|install\s+)[^\n]{0,60}(?:\.config/autostart/|/etc/systemd/system/|\.config/systemd/user/)[^\n]{0,60}\.(?:desktop|service))", re.I),
        "Writes an autostart entry or systemd unit file.",
    ),
    (
        "H013", "HEUR:AntiForensics.HistoryWipe", Severity.HIGH,
        re.compile(rb"(?:history\s+-c\b|unset\s+HISTFILE|export\s+HISTFILE=/dev/null|HISTSIZE=0\b|set\s+\+o\s+history)", re.I),
        "Disables or erases shell history to hide activity.",
    ),
    (
        "H014", "HEUR:AntiForensics.SelfDelete", Severity.MEDIUM,
        re.compile(rb"(?:rm\s+-[a-z]*f[a-z]*\s+(?:--\s+)?[\"']?\$0|shred\s+-[a-z]*u|rm\s+-[a-z]*f[a-z]*\s+[\"']?\$\{?BASH_SOURCE)", re.I),
        "Deletes its own file after running.",
    ),
    (
        "H015", "HEUR:Miner.Stratum", Severity.HIGH,
        # Only indicators that are meaningless outside mining. Bare family names
        # like "xmrig" or "randomx" appear as a CUPS printer model and as a
        # package name in lto-disabled-list respectively; the YARA CoinMiner
        # rule handles keyword *combinations*, which is the safe way to use them.
        re.compile(rb"(?:stratum\+(?:tcp|ssl)://|--donate-level)", re.I),
        "Cryptocurrency mining pool configuration.",
    ),
    (
        "H016", "HEUR:PrivEsc.SuidSudoers", Severity.HIGH,
        re.compile(rb"(?:chmod\s+[+u]*s\s|chmod\s+[0-7]?[4267][0-7]{3}\s|>>\s*/etc/sudoers|/etc/sudoers\.d/)", re.I),
        "Sets a setuid bit or edits sudoers - privilege escalation.",
    ),
    (
        "H017", "HEUR:Credential.SshKeyTheft", Severity.HIGH,
        # Requires an action against the credential file. PAM configs, sshd
        # configs and man pages all name /etc/shadow perfectly legitimately.
        # Only reading *out* a credential file counts here. Appending to
        # authorized_keys is what ssh-copy-id does legitimately; the malicious
        # form embeds a literal key blob, which Linux_Persistence_SSHKey covers.
        re.compile(
            rb"(?:cat|cp|scp|tar|curl|wget|base64|xxd|head|dd\s+if=)\s+[^\n]{0,80}"
            rb"(?:\.ssh/id_(?:rsa|ed25519|dsa)\b|/etc/shadow)",
            re.I,
        ),
        "Reads out or exfiltrates SSH private keys or the shadow password file.",
    ),
    (
        "H018", "HEUR:Defense.DisableSecurity", Severity.HIGH,
        re.compile(rb"(?:systemctl\s+(?:stop|disable|mask)\s+(?:ufw|firewalld|apparmor|clamav|auditd)|setenforce\s+0|iptables\s+-F)", re.I),
        "Disables a firewall, LSM, or security service.",
    ),
    (
        "H019", "HEUR:Recon.MassScan", Severity.LOW,
        re.compile(rb"(?:for\s+i\s+in\s+\$\(seq[^\n]{0,60}\)[^\n]{0,60}(?:nc|ping)|nmap\s+-[a-z]*s[SVA])", re.I),
        "Performs network scanning or sweeping.",
    ),
    # The three encoding indicators below are LOW on purpose: they describe how
    # data is represented, not what it does. Embedded images in SVGs, X.509
    # certificates, crypto constants and minified JavaScript all look exactly
    # like this. They corroborate; the YARA rule Trojan.Script.Obfuscated is
    # what actually convicts, because it also requires a decode call and an
    # execution sink.
    (
        "H020", "HEUR:Obfuscation.LongBase64", Severity.LOW,
        # Bounded for the same reason as the YARA rule: proving a long blob
        # exists does not require matching all of it.
        re.compile(rb"[A-Za-z0-9+/]{600,700}"),
        "Long base64 blob. Common in legitimate files; only meaningful alongside a decode-and-execute step.",
    ),
    (
        "H021", "HEUR:Obfuscation.HexBlob", Severity.LOW,
        re.compile(rb"(?:\\x[0-9a-fA-F]{2}){150,}"),
        "Large hex-escaped byte blob - may be an embedded payload, or ordinary binary constants.",
    ),
    (
        "H022", "HEUR:Obfuscation.CharCodeBuild", Severity.LOW,
        # A bare String.fromCharCode( call is everyday JavaScript; only a long
        # chain of them suggests deliberate string hiding.
        re.compile(rb"(?:chr\s*\(\s*\d{1,3}\s*\)\s*\+\s*){8,}"
                   rb"|(?:String\.fromCharCode\s*\(\s*\d{1,3}\s*(?:,\s*\d{1,3}\s*){6,}\))", re.I),
        "Builds a string character-by-character to evade static inspection.",
    ),
    (
        "H023", "HEUR:Dropper.EmbeddedELF", Severity.HIGH,
        re.compile(rb"(?:^|[\n'\"\s])\x7fELF[\x01\x02][\x01\x02]"),
        "An ELF executable is embedded inside a text/script file.",
    ),
    (
        "H024", "HEUR:Evasion.SleepBeacon", Severity.LOW,
        re.compile(rb"while\s+(?:true|:)\s*;\s*do[^\n]{0,200}(?:curl|wget|nc)\b[^\n]{0,200}sleep\s+\d+", re.I | re.S),
        "Beacon loop: repeatedly contacts a host on a timer.",
    ),
]

# Filenames whose extension claims one thing while the content says another.
RTL_OVERRIDE = re.compile(r"[‪-‮⁦-⁩]")
DOUBLE_EXT = re.compile(r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|txt|mp3|mp4)\.(sh|bash|py|pl|exe|run|bin|elf|scr|com)$", re.I)


def shannon_entropy(data: bytes) -> float:
    """Bits of entropy per byte (0.0-8.0). ~7.9+ means compressed or encrypted."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_text(data: bytes) -> bool:
    """Heuristic text detection: no NUL bytes and mostly printable."""
    probe = data[:TEXT_PROBE]
    if not probe:
        return False
    if b"\x00" in probe:
        return False
    printable = sum(1 for b in probe if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(probe) >= 0.90


class ElfInfo:
    """Minimal ELF reader - just enough for packer and structure heuristics."""

    __slots__ = ("valid", "is_64", "little", "etype", "sections", "section_count", "error")

    def __init__(self, data: bytes) -> None:
        self.valid = False
        self.is_64 = False
        self.little = True
        self.etype = 0
        self.sections: list[tuple[str, int, int]] = []  # (name, offset, size)
        self.section_count = 0
        self.error = ""
        try:
            self._parse(data)
        except (struct.error, IndexError, ValueError, UnicodeDecodeError) as exc:
            self.error = str(exc)

    def _parse(self, data: bytes) -> None:
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return
        self.valid = True
        self.is_64 = data[4] == 2
        self.little = data[5] == 1
        endian = "<" if self.little else ">"

        if self.is_64:
            self.etype, = struct.unpack_from(endian + "H", data, 16)
            e_shoff, = struct.unpack_from(endian + "Q", data, 0x28)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x3A)
            sh_fmt, name_off, off_off, size_off = endian + "I", 0, 0x18, 0x20
        else:
            self.etype, = struct.unpack_from(endian + "H", data, 16)
            e_shoff, = struct.unpack_from(endian + "I", data, 0x20)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 0x2E)
            sh_fmt, name_off, off_off, size_off = endian + "I", 0, 0x10, 0x14

        self.section_count = e_shnum
        if not e_shoff or not e_shnum or e_shstrndx >= e_shnum:
            return
        if e_shoff + e_shnum * e_shentsize > len(data):
            return  # truncated read; sections simply unavailable

        # Locate the section-header string table first.
        strtab_hdr = e_shoff + e_shstrndx * e_shentsize
        str_off, = struct.unpack_from(endian + ("Q" if self.is_64 else "I"), data, strtab_hdr + off_off)
        str_size, = struct.unpack_from(endian + ("Q" if self.is_64 else "I"), data, strtab_hdr + size_off)
        strtab = data[str_off:str_off + str_size]

        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            nameidx, = struct.unpack_from(sh_fmt, data, base + name_off)
            offset, = struct.unpack_from(endian + ("Q" if self.is_64 else "I"), data, base + off_off)
            size, = struct.unpack_from(endian + ("Q" if self.is_64 else "I"), data, base + size_off)
            end = strtab.find(b"\x00", nameidx)
            name = strtab[nameidx:end if end != -1 else None].decode("ascii", "replace")
            self.sections.append((name, offset, size))


class Heuristics:
    """Scores a file across structural and behavioural checks."""

    def analyze(self, path: Path, data: bytes) -> list[Detection]:
        detections: list[Detection] = []
        detections.extend(self._name_checks(path))

        if data[:4] == b"\x7fELF":
            detections.extend(self._elf_checks(path, data))
        elif is_text(data):
            detections.extend(self._text_checks(data))

        detections.extend(self._context_checks(path, data))
        return detections

    # -------------------------------------------------------------- filename

    def _name_checks(self, path: Path) -> list[Detection]:
        out: list[Detection] = []
        name = path.name

        if RTL_OVERRIDE.search(name):
            out.append(Detection(
                "HEUR:Masquerade.RTLOverride", "heuristics", Severity.HIGH,
                "Filename contains a bidirectional override character, used to disguise the real extension.",
                evidence=repr(name),
            ))

        if DOUBLE_EXT.search(name):
            out.append(Detection(
                "HEUR:Masquerade.DoubleExtension", "heuristics", Severity.MEDIUM,
                "Filename pairs a document extension with an executable one.",
                evidence=name,
            ))
        return out

    # ------------------------------------------------------------------- ELF

    def _elf_checks(self, path: Path, data: bytes) -> list[Detection]:
        out: list[Detection] = []
        elf = ElfInfo(data)
        if not elf.valid:
            return out

        section_names = {name for name, _, _ in elf.sections}

        # Structural signals are deliberately LOW: on their own they describe
        # unusual build choices, not malice. They matter when they corroborate
        # something else, so they must not reach the suspicion threshold alone.
        if any(n.startswith(("UPX", ".upx")) for n in section_names) or b"UPX!" in data[:4096]:
            out.append(Detection(
                "HEUR:Packer.UPX", "heuristics", Severity.LOW,
                "Executable is UPX-packed. Legitimate for some software, but also standard malware practice.",
                evidence="UPX section/magic",
            ))

        if elf.section_count == 0:
            out.append(Detection(
                "HEUR:Structure.NoSectionHeaders", "heuristics", Severity.LOW,
                "ELF has no section header table - typically stripped to frustrate analysis.",
                evidence="e_shnum=0",
            ))

        entropy = shannon_entropy(data[:ENTROPY_SAMPLE])
        if entropy >= 7.8:
            out.append(Detection(
                "HEUR:Entropy.PackedExecutable", "heuristics", Severity.MEDIUM,
                "Executable is almost entirely high-entropy data, indicating packing or encryption.",
                evidence=f"entropy={entropy:.2f}/8.00",
            ))
        elif entropy >= 7.2 and section_names and not section_names & {".text", ".rodata"}:
            out.append(Detection(
                "HEUR:Entropy.OpaqueExecutable", "heuristics", Severity.LOW,
                "High-entropy executable with no recognisable code sections.",
                evidence=f"entropy={entropy:.2f}/8.00",
            ))

        # An ELF wearing a document's extension is essentially always deceptive.
        if path.suffix.lower() in DOCUMENT_EXTENSIONS:
            out.append(Detection(
                "HEUR:Masquerade.ExecutableAsDocument", "heuristics", Severity.HIGH,
                f"File is an ELF executable but is named like a {path.suffix} document.",
                evidence=f"magic=ELF ext={path.suffix}",
            ))
        return out

    # ------------------------------------------------------------------ text

    def _text_checks(self, data: bytes) -> list[Detection]:
        out: list[Detection] = []
        for _rid, name, severity, pattern, description in TEXT_RULES:
            match = pattern.search(data)
            if match:
                snippet = match.group(0)[:120]
                out.append(Detection(
                    name, "heuristics", severity, description,
                    evidence=snippet.decode("utf-8", "replace").replace("\n", "\\n"),
                ))
        return out

    # --------------------------------------------------------------- context

    def _context_checks(self, path: Path, data: bytes) -> list[Detection]:
        out: list[Detection] = []
        try:
            st = path.lstat()
        except OSError:
            return out

        mode = st.st_mode
        parts = path.parts

        if mode & 0o4000 and any(p in ("/tmp", "/var/tmp", "/dev/shm") for p in (str(path.parent),)):
            out.append(Detection(
                "HEUR:PrivEsc.SuidInTemp", "heuristics", Severity.CRITICAL,
                "Setuid binary in a world-writable temporary directory - a classic privilege-escalation backdoor.",
                evidence=f"mode={oct(mode & 0o7777)}",
            ))
        elif mode & 0o4000 and str(path).startswith(str(Path.home())):
            out.append(Detection(
                "HEUR:PrivEsc.SuidInHome", "heuristics", Severity.HIGH,
                "Setuid binary inside a home directory.",
                evidence=f"mode={oct(mode & 0o7777)}",
            ))

        # A hidden executable staged in a temp directory is a strong staging signal.
        in_temp = any(str(path).startswith(t) for t in ("/tmp/", "/var/tmp/", "/dev/shm/"))
        if in_temp and path.name.startswith(".") and mode & 0o111 and data[:4] == b"\x7fELF":
            out.append(Detection(
                "HEUR:Staging.HiddenExecInTemp", "heuristics", Severity.HIGH,
                "Hidden executable staged in a temporary directory.",
                evidence=str(path),
            ))

        # Autostart entries that launch an interpreter from a temp path.
        if ".config" in parts and "autostart" in parts and is_text(data):
            if re.search(rb"Exec=.*(?:/tmp/|/dev/shm/|curl|wget|base64)", data, re.I):
                out.append(Detection(
                    "HEUR:Persistence.SuspiciousAutostart", "heuristics", Severity.HIGH,
                    "Autostart entry executes from a temporary path or fetches remote code.",
                    evidence="autostart Exec=",
                ))
        return out
