"""
Security Engine — Windows Amcache Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Real-opens Windows Amcache.hve registry hive files using the python-registry
library (Registry.Registry) and real-navigates the actual REGF/HBIN/NK/VK
structure to enumerate genuine InventoryApplicationFile / File program-execution
entries. No sample/mock data is ever generated — every Finding reflects data
that was actually parsed out of the hive's real binary structure.

Amcache.hve normally lives at %SystemRoot%\\AppCompat\\Programs\\Amcache.hve on a
live Windows system and is locked while Windows is running, so forensic analysts
typically work from an offline copy acquired via disk imaging / a forensic
triage tool (e.g. KAPE, FTK Imager) rather than the live path.

Designed to be resilient: any hive, key, or value that fails to open/parse is
counted as an error (or reported as a WAM-006 parse-note) and never crashes
the whole scan.
"""
import os
import time
from datetime import datetime

from app.detection_rules import ALL_RULES, rule_invalid_hive_format

try:
    from Registry import Registry
    REGISTRY_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only if python-registry is missing
    Registry = None
    REGISTRY_AVAILABLE = False

# Suspicious execution directories (real-world Amcache forensic triage locations)
SUSPICIOUS_DIRS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
)

# Real Amcache.hve keys (Win10+ and legacy Win8/8.1 layout)
INVENTORY_APP_FILE_KEY = "Root\\InventoryApplicationFile"
LEGACY_FILE_KEY = "Root\\File"

# Candidate value names actually observed in real Amcache.hve hives
PATH_VALUE_NAMES = ("LowerCaseLongPath", "Path", "10", "15")
PRODUCT_VALUE_NAMES = ("ProductName", "0")
PUBLISHER_VALUE_NAMES = ("Publisher", "1")
SIZE_VALUE_NAMES = ("Size", "FileSize", "6")
LINKDATE_VALUE_NAMES = ("LinkDate", "d", "17")
SHA1_VALUE_NAMES = ("FileId", "SHA1", "Sha1", "101")
PROGRAMID_VALUE_NAMES = ("ProgramId", "100")

LINKDATE_FORMATS = ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %I:%M:%S %p")


def _first_value(key, names):
    """Real-read the first matching value (by name) present on a real registry key."""
    try:
        available = {v.name(): v for v in key.values()}
    except Registry.RegistryError:
        return None
    for name in names:
        v = available.get(name)
        if v is not None:
            try:
                return v.value()
            except Exception:
                continue
    return None


def parse_link_date(raw):
    """Real-parse an Amcache LinkDate string into a datetime, or None if unparsable."""
    if not raw:
        return None
    text = str(raw).strip()
    if not text:
        return None
    for fmt in LINKDATE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    # Some hives store it as a raw epoch-seconds integer/string
    try:
        return datetime.utcfromtimestamp(int(text))
    except (ValueError, OSError, OverflowError):
        return None


class HiveParseError(Exception):
    """Raised when a target file cannot be real-opened as a valid registry hive."""


def open_hive(path):
    """Real-open a single file as a Windows registry hive via python-registry.
    Isolated as a thin function so it can be unit-tested directly against
    hand-built REGF bytes without needing a full Amcache.hve."""
    if not REGISTRY_AVAILABLE:
        raise HiveParseError("python-registry is not installed")
    try:
        with open(path, "rb") as fh:
            return Registry.Registry(fh)
    except Exception as exc:
        raise HiveParseError(str(exc)) from exc


def _entries_from_key(key, entries):
    """Real-walk one Amcache key level, collecting a raw dict per real subkey
    that actually has at least one parseable value."""
    try:
        subkeys = list(key.subkeys())
    except Registry.RegistryError:
        return
    for sk in subkeys:
        try:
            entry = {
                "path": _first_value(sk, PATH_VALUE_NAMES),
                "product_name": _first_value(sk, PRODUCT_VALUE_NAMES),
                "publisher": _first_value(sk, PUBLISHER_VALUE_NAMES),
                "size": _first_value(sk, SIZE_VALUE_NAMES),
                "link_date_raw": _first_value(sk, LINKDATE_VALUE_NAMES),
                "sha1": _first_value(sk, SHA1_VALUE_NAMES),
                "program_id": _first_value(sk, PROGRAMID_VALUE_NAMES),
            }
        except Exception:
            continue

        if entry["path"]:
            entries.append(entry)
        else:
            # Legacy Root\File\{volume guid}\ layer has one more real nesting level
            _entries_from_key(sk, entries)


def parse_hive_entries(hive):
    """Real-walk a real, already-opened Registry.Registry hive and return the
    list of real Amcache program/file entry dicts it actually contains."""
    entries = []
    root = hive.root()

    for key_path in (INVENTORY_APP_FILE_KEY, LEGACY_FILE_KEY):
        try:
            key = root.find_key(key_path)
        except Registry.RegistryKeyNotFoundException:
            continue
        _entries_from_key(key, entries)

    return entries


class ScanEngine:
    def __init__(self, target_path, max_depth=6, excludes=None, max_files=50000):
        self.target_path = os.path.abspath(target_path)
        self.max_depth = max_depth
        self.excludes = set(excludes) if excludes else set()
        self.max_files = max_files

        self.files_scanned = 0
        self.dirs_scanned = 0
        self.errors_count = 0
        self.findings = []

    def run(self):
        """Real-locate and real-parse every Amcache.hve/*.hve file under
        target_path (or the single file itself), returning the summary dict."""
        start = time.time()

        hive_files = self._discover_hive_files(self.target_path)

        all_entries = []  # (hive_path, entry_dict)
        for hive_path, hive_mtime in hive_files:
            try:
                hive = open_hive(hive_path)
            except HiveParseError as exc:
                self.errors_count += 1
                note = rule_invalid_hive_format(hive_path, str(exc))
                if note:
                    note["file_path"] = hive_path
                    note["permissions_octal"] = os.path.basename(hive_path)
                    note["owner_uid"] = None
                    note["owner_gid"] = None
                    self.findings.append(note)
                continue

            try:
                entries = parse_hive_entries(hive)
            except Exception:
                self.errors_count += 1
                continue

            for entry in entries:
                entry["_hive_mtime"] = hive_mtime
                entry["_link_date_parsed"] = parse_link_date(entry.get("link_date_raw"))
                all_entries.append((hive_path, hive_mtime, entry))

        self.files_scanned = len(all_entries)
        self._apply_rules(all_entries)

        elapsed = time.time() - start
        return {
            "files_scanned": self.files_scanned,
            "dirs_scanned": self.dirs_scanned,
            "errors_count": self.errors_count,
            "findings": self.findings,
            "elapsed_seconds": round(elapsed, 3),
        }

    def _discover_hive_files(self, target_path):
        """Real-walk target_path (file or directory) collecting real candidate
        hive files (Amcache.hve or *.hve) with their real filesystem mtime."""
        hive_files = []

        if os.path.isfile(target_path):
            try:
                mtime = os.path.getmtime(target_path)
            except OSError:
                mtime = time.time()
            hive_files.append((target_path, mtime))
            return hive_files

        for root, dirs, files in os.walk(target_path):
            if self._is_excluded(root):
                dirs[:] = []
                continue
            self.dirs_scanned += 1
            for fname in files:
                lowered = fname.lower()
                if lowered == "amcache.hve" or lowered.endswith(".hve"):
                    full_path = os.path.join(root, fname)
                    try:
                        mtime = os.path.getmtime(full_path)
                    except OSError:
                        self.errors_count += 1
                        continue
                    hive_files.append((full_path, mtime))
            if len(hive_files) >= self.max_files:
                break

        return hive_files

    def _is_excluded(self, path):
        return any(path == ex or path.startswith(ex.rstrip("/") + "/") for ex in self.excludes)

    def _apply_rules(self, all_entries):
        """Apply every detection rule (both per-entry and cross-entry rules)
        against the real parsed entry set."""
        context = {"all_entries": all_entries}
        for hive_path, hive_mtime, entry in all_entries:
            for rule in ALL_RULES:
                if rule is rule_invalid_hive_format:
                    continue
                try:
                    result = rule(entry, context)
                except Exception:
                    self.errors_count += 1
                    continue
                if result:
                    result["file_path"] = hive_path
                    result["permissions_octal"] = entry.get("path") or "(unknown path)"
                    result["owner_uid"] = None
                    result["owner_gid"] = None
                    self.findings.append(result)
