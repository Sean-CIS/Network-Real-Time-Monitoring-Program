"""Port vulnerability hints for security scanning."""

PORT_HINTS: dict[int, dict] = {
    21: {"severity": "warning", "hint": "FTP - unencrypted protocol, consider SFTP"},
    22: {"severity": "info", "hint": "SSH - ensure key-based auth, disable password login"},
    23: {"severity": "critical", "hint": "Telnet - unencrypted remote access, use SSH instead"},
    25: {"severity": "warning", "hint": "SMTP - check for open relay configuration"},
    53: {"severity": "info", "hint": "DNS - ensure zone transfer restrictions"},
    80: {"severity": "info", "hint": "HTTP - unencrypted, consider HTTPS"},
    110: {"severity": "warning", "hint": "POP3 - unencrypted email, use POP3S"},
    135: {"severity": "warning", "hint": "MS-RPC - commonly targeted, restrict access"},
    139: {"severity": "warning", "hint": "NetBIOS - restrict to internal network only"},
    143: {"severity": "warning", "hint": "IMAP - unencrypted email, use IMAPS"},
    443: {"severity": "info", "hint": "HTTPS - verify TLS version and cipher suite"},
    445: {"severity": "critical", "hint": "SMB - check for EternalBlue patches (MS17-010)"},
    1433: {"severity": "warning", "hint": "MSSQL - do not expose to internet"},
    1521: {"severity": "warning", "hint": "Oracle DB - do not expose to internet"},
    3306: {"severity": "warning", "hint": "MySQL - do not expose to internet"},
    3389: {"severity": "critical", "hint": "RDP - high-value target, use VPN/MFA"},
    5432: {"severity": "warning", "hint": "PostgreSQL - do not expose to internet"},
    5900: {"severity": "critical", "hint": "VNC - unencrypted remote desktop, use VPN"},
    6379: {"severity": "warning", "hint": "Redis - requires authentication, do not expose"},
    8080: {"severity": "info", "hint": "HTTP alternate - verify this is intentional"},
    8443: {"severity": "info", "hint": "HTTPS alternate - verify this is intentional"},
    27017: {"severity": "warning", "hint": "MongoDB - requires authentication, do not expose"},
}

SECURITY_SCAN_PORTS = [
    21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445,
    1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
]
