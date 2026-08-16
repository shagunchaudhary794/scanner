"""
Unsupported-OS auto-fail detection.

PCI reference doc §7 (exact wording): "Determining the OS is a version no
longer supported by the vendor... must be marked as an automatic failure by
the ASV." §41 of the architecture doc lists "Unsupported Operating Systems"
as one of the is_auto_fail conditions.

Nmap's -O fingerprint returns free-text OS names (e.g. "Microsoft Windows
Server 2008 R2", "Linux 2.6.32 (CentOS 6)"), not structured vendor/version
fields, and there's no single canonical EOL API. We match against a curated
list of substrings for OS families with well-known, stable EOL dates.

This is a best-effort match, not exhaustive: an unmatched OS string means
"could not determine support status," not "supported." That distinction is
surfaced to the caller as a Special-Note-style informational finding rather
than silently doing nothing, so it doesn't misrepresent unknown as safe.
"""

from datetime import date

# (substring to match in the Nmap OS fingerprint, EOL date, canonical name)
# Ordered most-specific first so e.g. "Windows Server 2008 R2" doesn't get
# shadowed by a bare "Windows Server 2008" entry ordering issue.
_EOL_OS_TABLE = [
    # Windows Desktop
    ("Windows XP", date(2014, 4, 8), "Windows XP"),
    ("Windows Vista", date(2017, 4, 11), "Windows Vista"),
    ("Windows 7", date(2020, 1, 14), "Windows 7"),
    ("Windows 8.1", date(2023, 1, 10), "Windows 8.1"),
    ("Windows 8", date(2016, 1, 12), "Windows 8"),
    # Windows Server
    ("Windows Server 2003", date(2015, 7, 14), "Windows Server 2003"),
    ("Windows Server 2008 R2", date(2020, 1, 14), "Windows Server 2008 R2"),
    ("Windows Server 2008", date(2020, 1, 14), "Windows Server 2008"),
    ("Windows Server 2012 R2", date(2023, 10, 10), "Windows Server 2012 R2"),
    ("Windows Server 2012", date(2023, 10, 10), "Windows Server 2012"),
    # RHEL / CentOS
    ("Red Hat Enterprise Linux 5", date(2017, 3, 31), "RHEL 5"),
    ("RHEL 5", date(2017, 3, 31), "RHEL 5"),
    ("Red Hat Enterprise Linux 6", date(2020, 11, 30), "RHEL 6"),
    ("RHEL 6", date(2020, 11, 30), "RHEL 6"),
    ("Red Hat Enterprise Linux 7", date(2024, 6, 30), "RHEL 7"),
    ("RHEL 7", date(2024, 6, 30), "RHEL 7"),
    ("CentOS 6", date(2020, 11, 30), "CentOS 6"),
    ("CentOS 7", date(2024, 6, 30), "CentOS 7"),
    ("CentOS 8", date(2021, 12, 31), "CentOS 8"),  # early EOL, replaced by Stream
    # Debian / Ubuntu
    ("Ubuntu 14.04", date(2019, 4, 30), "Ubuntu 14.04 LTS"),
    ("Ubuntu 16.04", date(2021, 4, 30), "Ubuntu 16.04 LTS"),
    ("Ubuntu 18.04", date(2023, 5, 31), "Ubuntu 18.04 LTS"),
    ("Debian 8", date(2020, 6, 30), "Debian 8 (Jessie)"),
    ("Debian 9", date(2022, 6, 30), "Debian 9 (Stretch)"),
    ("Debian 10", date(2024, 6, 30), "Debian 10 (Buster)"),
    # Legacy kernels seen in bare "Linux x.y" fingerprints
    ("Linux 2.4", date(2011, 12, 1), "Linux kernel 2.4.x"),
    ("Linux 2.6", date(2016, 2, 1), "Linux kernel 2.6.x"),
    # BSD / Solaris
    ("Solaris 9", date(2014, 10, 1), "Solaris 9"),
    ("Solaris 10", date(2024, 1, 1), "Solaris 10"),
    ("FreeBSD 10", date(2018, 10, 31), "FreeBSD 10"),
    ("FreeBSD 11", date(2021, 9, 30), "FreeBSD 11"),
]


def check_eol(os_fingerprint: str, as_of: date = None):
    """Given an Nmap OS fingerprint string, return a dict describing
    support status, or None if the string doesn't match anything in the
    table (support status unknown, not asserted as safe).

    Returns: {'matched_name': str, 'eol_date': date, 'is_eol': bool} | None
    """
    if not os_fingerprint:
        return None
    as_of = as_of or date.today()

    for needle, eol_date, canonical in _EOL_OS_TABLE:
        if needle.lower() in os_fingerprint.lower():
            return {
                'matched_name': canonical,
                'eol_date': eol_date,
                'is_eol': as_of >= eol_date,
            }
    return None
