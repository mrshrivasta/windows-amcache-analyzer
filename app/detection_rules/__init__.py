"""
Detection Rules — Windows Amcache Analyzer
Developed by Karanam Shrivasta | https://github.com/mrshrivasta

Each rule inspects a REAL entry dict that was actually parsed out of a real
Amcache.hve registry hive (InventoryApplicationFile / legacy File key values)
and returns a Finding dict if the condition is met. Rules are intentionally
conservative, documented, and independently verifiable by opening the same
hive with any other Amcache-aware tool (e.g. Eric Zimmerman's AmcacheParser).
"""
import os
import ntpath
import posixpath

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

SUSPICIOUS_DIRS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
)

DOUBLE_EXTENSION_PATTERNS = (
    ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
    ".jpg.exe", ".jpeg.exe", ".png.exe", ".txt.exe", ".zip.exe",
    ".pdf.scr", ".doc.scr", ".jpg.scr", ".txt.scr",
    ".pdf.bat", ".doc.bat",
)


def _basename(path):
    """Real basename extraction that tolerates Windows-style backslash paths
    regardless of the host OS this analyzer itself runs on."""
    if not path:
        return ""
    return ntpath.basename(path) if "\\" in path else posixpath.basename(path)


def rule_unsigned_suspicious_location(entry, context=None):
    """WAM-001: A real parsed Amcache entry has no Publisher recorded AND its
    real path sits in a directory commonly abused to stage/execute unsigned
    malware (Temp, Public, ProgramData, Downloads). Forensic relevance: real
    attackers frequently drop and execute unsigned binaries from these
    user-writable locations because they don't require elevated privileges
    and are rarely monitored as closely as Program Files."""
    path = entry.get("path")
    publisher = (entry.get("publisher") or "").strip()
    if not path:
        return None
    lowered = path.lower()
    if publisher:
        return None
    if any(marker in lowered for marker in SUSPICIOUS_DIRS):
        return {
            "rule_id": "WAM-001",
            "rule_name": "Unsigned Binary in Suspicious Execution Location",
            "severity": SEVERITY_HIGH,
            "description": (
                f"{path} was executed with no Publisher recorded in Amcache and "
                f"resides in a commonly-abused staging directory. Unsigned "
                f"binaries executed from Temp/Public/ProgramData/Downloads are "
                f"a strong malware-execution indicator worth triage."
            ),
        }
    return None


def rule_extension_spoofing(entry, context=None):
    """WAM-002: A real parsed Amcache entry's path shows a double-extension /
    icon-spoofing pattern (e.g. invoice.pdf.exe). Forensic relevance: this is
    a classic social-engineering trick where a malicious executable is named
    to look like a document/image so a victim double-clicks it in Explorer,
    which by default hides the real trailing extension."""
    path = entry.get("path")
    if not path:
        return None
    lowered = path.lower()
    for pattern in DOUBLE_EXTENSION_PATTERNS:
        if lowered.endswith(pattern):
            return {
                "rule_id": "WAM-002",
                "rule_name": "Double-Extension / Icon Spoofing Pattern",
                "severity": SEVERITY_MEDIUM,
                "description": (
                    f"{path} has a double-extension pattern ('{pattern}') "
                    f"consistent with an executable disguised as a document/"
                    f"image to trick a user into running it."
                ),
            }
    return None


def rule_future_link_date(entry, context=None):
    """WAM-003: A real parsed Amcache entry's LinkDate (PE compile/link
    timestamp) is later than the real hive file's own filesystem mtime.
    Forensic relevance: a binary claiming to have been compiled AFTER the
    system captured execution evidence of it is a timeline anomaly — it
    indicates either system clock tampering at execution time or a forged/
    spoofed PE header timestamp, both of which are anti-forensic techniques."""
    link_date = entry.get("_link_date_parsed")
    hive_mtime = entry.get("_hive_mtime")
    if link_date is None or hive_mtime is None:
        return None
    if link_date.timestamp() > hive_mtime:
        return {
            "rule_id": "WAM-003",
            "rule_name": "Future-Dated LinkDate (PE Timestamp Anomaly)",
            "severity": SEVERITY_LOW,
            "description": (
                f"{entry.get('path')} has a LinkDate ({link_date}) later than "
                f"the Amcache.hve file's own modification time on disk — a "
                f"timeline anomaly consistent with clock tampering or a "
                f"spoofed PE compile timestamp."
            ),
        }
    return None


def rule_duplicate_basename_multiple_paths(entry, context=None):
    """WAM-004: The same real filename (basename) appears in two or more
    real parsed entries with different real full paths. Forensic relevance:
    legitimate applications are normally executed from one canonical
    install location; the same-named binary present/executed from multiple
    locations (e.g. C:\\Windows\\svchost.exe AND C:\\Users\\Public\\svchost.exe)
    is a classic masquerading/persistence indicator."""
    path = entry.get("path")
    if not path or not context:
        return None
    name = _basename(path).lower()
    if not name:
        return None
    all_entries = context.get("all_entries", [])
    other_paths = {
        e.get("path") for (_h, _m, e) in all_entries
        if e.get("path") and _basename(e["path"]).lower() == name and e.get("path") != path
    }
    if other_paths:
        return {
            "rule_id": "WAM-004",
            "rule_name": "Duplicate Basename Across Multiple Paths",
            "severity": SEVERITY_MEDIUM,
            "description": (
                f"'{_basename(path)}' was executed from {path} but also seen "
                f"at {len(other_paths)} other distinct path(s) "
                f"({', '.join(sorted(other_paths))}) — possible masquerading "
                f"or unauthorized copies of the same-named binary."
            ),
        }
    return None


def rule_missing_hash(entry, context=None):
    """WAM-005: A real parsed Amcache entry has no SHA1/FileId hash recorded
    at all. Forensic relevance: without a hash, the executed binary cannot be
    checked against hash-reputation sources (VirusTotal, NSRL, internal
    allow/deny lists), leaving an integrity-verification gap for that
    specific execution event."""
    path = entry.get("path")
    if not path:
        return None
    sha1 = entry.get("sha1")
    if sha1:
        return None
    return {
        "rule_id": "WAM-005",
        "rule_name": "Missing Hash — Integrity Verification Gap",
        "severity": SEVERITY_LOW,
        "description": (
            f"{path} has no SHA1/FileId value recorded in Amcache, so it "
            f"cannot be checked against hash-reputation databases."
        ),
    }


def rule_invalid_hive_format(target_path, error_message):
    """WAM-006: The target file could not be real-opened as a valid registry
    hive at all (wrong REGF signature or corrupt structure). Forensic
    relevance: reported as an informational parse-note rather than a crash,
    so an analyst pointed at a directory of mixed evidence still gets results
    for every hive that IS valid."""
    return {
        "rule_id": "WAM-006",
        "rule_name": "Invalid or Corrupt Registry Hive",
        "severity": SEVERITY_LOW,
        "description": (
            f"{target_path} could not be opened as a valid Windows registry "
            f"hive ({error_message}). It was skipped; no entries from it were "
            f"parsed."
        ),
    }


ALL_RULES = [
    rule_unsigned_suspicious_location,
    rule_extension_spoofing,
    rule_future_link_date,
    rule_duplicate_basename_multiple_paths,
    rule_missing_hash,
    rule_invalid_hive_format,
]
