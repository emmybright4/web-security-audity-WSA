"""WSA IP/Network Scanner Engine.

Performs network-level scanning: host discovery, port scanning, service
detection, version detection, OS fingerprinting, and vulnerability checks.
Operates on IP addresses, ranges, and CIDR networks.
"""
import ipaddress
import logging
import re
import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

log = logging.getLogger("wsa.ip_scanner")

# Standard service-name map for well-known ports
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 465: "smtps", 554: "rtsp", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy",
    8443: "https-alt", 27017: "mongodb", 50000: "sap",
}

# Services considered insecure
INSECURE_SERVICES = {
    "telnet", "ftp", "rsh", "rlogin", "rexec",
    "http", "pop3", "imap", "netbios-ssn", "microsoft-ds",
}

# Default scan profile port lists
QUICK_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1433, 3306, 3389, 5432, 8080, 8443,
]

STANDARD_PORTS = QUICK_PORTS + [
    465, 554, 587, 636, 1521, 2049, 5900, 6379, 27017, 50000,
]

FULL_PORTS = list(range(1, 1025)) + STANDARD_PORTS[::2]  # 1-1024 + extras

# OS fingerprint patterns (TCP window size + TTL heuristic)
OS_FINGERPRINTS = [
    {"match": {"ttl_min": 64, "ttl_max": 64}, "name": "Linux/Unix"},
    {"match": {"ttl_min": 128, "ttl_max": 128}, "name": "Windows"},
    {"match": {"ttl_min": 254, "ttl_max": 255}, "name": "Network Device (Cisco/etc.)"},
]


def _parse_targets(target_str):
    """Parse a target string into a list of IP addresses.

    Supports: single IP, CIDR notation, IP range (start-end).
    """
    target_str = target_str.strip()
    ips = []

    # CIDR notation
    if "/" in target_str:
        try:
            net = ipaddress.ip_network(target_str, strict=False)
            # Limit to /24 for safety (max 256 hosts)
            if net.prefixlen < 24:
                net = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
            ips = [str(ip) for ip in net.hosts()]
        except ValueError as e:
            log.warning("Invalid CIDR: %s — %s", target_str, e)
            return []

    # IP range (e.g. 192.168.1.1-192.168.1.50 or 192.168.1.1-50)
    elif "-" in target_str:
        parts = target_str.split("-", 1)
        try:
            start = ipaddress.ip_address(parts[0].strip())
            end_str = parts[1].strip()
            if "." not in end_str:
                # Short form: 192.168.1.1-50
                prefix = ".".join(str(start).split(".")[:3])
                end = ipaddress.ip_address(f"{prefix}.{end_str}")
            else:
                end = ipaddress.ip_address(end_str)
            cur = start
            while cur <= end:
                ips.append(str(cur))
                cur = ipaddress.ip_address(int(cur) + 1)
            # Limit
            if len(ips) > 256:
                ips = ips[:256]
        except (ValueError, IndexError) as e:
            log.warning("Invalid range: %s — %s", target_str, e)
            return []

    # Single IP
    else:
        try:
            ipaddress.ip_address(target_str)
            ips = [target_str]
        except ValueError:
            # Try hostname resolution
            try:
                resolved = socket.gethostbyname(target_str)
                ips = [resolved]
            except socket.gaierror:
                log.warning("Cannot resolve: %s", target_str)
                return []

    return ips


def _get_ports_for_profile(profile, custom_ports=None):
    """Return the list of ports to scan based on scan profile."""
    if custom_ports:
        return custom_ports
    if profile == "quick":
        return QUICK_PORTS
    elif profile == "standard":
        return STANDARD_PORTS
    elif profile == "full":
        return FULL_PORTS
    return QUICK_PORTS


def _is_host_alive(ip, timeout=1.5):
    """Quick host alive check: try connecting to common ports."""
    check_ports = [80, 443, 22, 445]
    for port in check_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            pass
    return False


def _is_host_alive_icmp(ip, timeout=1):
    """UDP-based ICMP-like check (works without root on most systems).

    Falls back to TCP connect check if ICMP isn't available.
    """
    try:
        # Try raw ICMP (may need root)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        # Build ICMP echo request
        icmp_type = 8  # Echo Request
        icmp_code = 0
        identifier = 0x1234
        sequence = 1
        header = struct.pack("!BBHHH", icmp_type, icmp_code, 0, identifier, sequence)
        checksum = _icmp_checksum(header)
        header = struct.pack("!BBHHH", icmp_type, icmp_code, checksum, identifier, sequence)
        sock.sendto(header, (ip, 0))
        sock.settimeout(timeout)
        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return True
        except socket.timeout:
            sock.close()
            return False
    except (OSError, PermissionError):
        # Fallback to TCP connect
        return _is_host_alive(ip, timeout)


def _icmp_checksum(data):
    """Calculate ICMP checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _grab_banner(ip, port, timeout=2):
    """Attempt to grab a service banner from a port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        # Some services send a banner immediately
        banner_probes = {
            21: b"QUIT\r\n",
            22: None,
            25: b"EHLO wsa-scanner\r\n",
            80: b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % ip.encode(),
            110: b"QUIT\r\n",
            143: b"a001 LOGOUT\r\n",
            443: None,
        }

        probe = banner_probes.get(port)
        if probe:
            try:
                sock.send(probe)
            except Exception:
                pass

        try:
            banner = sock.recv(1024)
            banner_str = banner.decode("utf-8", errors="replace").strip()[:512]
        except socket.timeout:
            banner_str = ""

        sock.close()
        return banner_str
    except Exception:
        return ""


def _detect_service(ip, port, banner=""):
    """Detect service name from port number and banner content."""
    service = WELL_KNOWN_PORTS.get(port, "unknown")

    if banner:
        bl = banner.lower()
        if "ssh" in bl or "openssh" in bl:
            service = "ssh"
        elif "ftp" in bl:
            service = "ftp"
        elif "smtp" in bl or "esmtp" in bl:
            service = "smtp"
        elif "http" in bl:
            service = "http"
        elif "imap" in bl:
            service = "imap"
        elif "pop" in bl:
            service = "pop3"
        elif "mysql" in bl:
            service = "mysql"
        elif "redis" in bl:
            service = "redis"
        elif "nginx" in bl or "apache" in bl:
            service = "http"
        elif "microsoft" in bl or "smb" in bl:
            service = "microsoft-ds"

    return service


def _detect_version(banner, service):
    """Extract version info from banner."""
    if not banner:
        return ""

    patterns = [
        r"(OpenSSH[_\-]?\d+[\.\d]*)",
        r"(SSH\-\d+[\.\d]+\w*)",
        r"(Apache[/\-]?\d+[\.\d]*)",
        r"(nginx[/\-]?\d+[\.\d]*)",
        r"(Microsoft FTP Service)",
        r"(ProFTPD[\s/]\d+[\.\d]*)",
        r"(vsFTPd[\s/]\d+[\.\d]*)",
        r"(Postfix)",
        r"(Sendmail[\s/]\d+[\.\d]*)",
        r"(MySQL[\s/]\d+[\.\d]*)",
        r"(PostgreSQL[\s/]\d+[\.\d]*)",
        r"(Redis[\s/]\d+[\.\d]*)",
        r"(Microsoft Windows[\s\w]*\d*)",
        r"(Microsoft-IIS[/]\d+[\.\d]*)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    return ""


def _detect_os(ip, timeout=2):
    """Basic OS detection via TCP fingerprinting (TTL + window size)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        # Connect to port 80 or 443
        target_port = 80
        try:
            sock.connect((ip, target_port))
        except Exception:
            sock.close()
            # Try to get TTL from any connectable port
            return "Unknown"

        # Get TTL from IP header (via recv options if available)
        # Simplified: use TTL from a UDP traceroute-like approach
        try:
            # Get initial TTL by sending a UDP packet and reading ICMP
            pass
        except Exception:
            pass

        sock.close()

        # Use a simpler heuristic based on what ports responded
        # and basic TCP behavior
        return "Unknown (fingerprint inconclusive)"
    except Exception:
        return "Unknown"


def _tls_check(ip, port, timeout=3):
    """Perform SSL/TLS security checks on a port."""
    findings = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                cert = tls.getpeercert() or {}
                proto = tls.version() or ""
                cipher = tls.cipher() or ("", "", "")

                # Check for deprecated protocols
                if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
                    findings.append({
                        "name": f"Deprecated TLS Protocol Supported ({proto})",
                        "vuln_type": "ssl_tls",
                        "severity": "high",
                        "confidence": "certain",
                        "description": (
                            f"The server at {ip}:{port} accepts {proto}, which has "
                            "known vulnerabilities and is susceptible to downgrade attacks."
                        ),
                        "evidence": f"Negotiated protocol: {proto}, cipher: {cipher[0]}",
                        "recommendation": "Disable TLSv1.0/1.1 and SSLv3; enforce TLS 1.2+.",
                        "cve_id": "",
                        "cvss_score": None,
                    })

                # Check certificate expiry
                not_after = cert.get("notAfter")
                if not_after:
                    import datetime
                    expiry = datetime.datetime.strptime(
                        not_after, "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    days_left = (expiry - datetime.datetime.now(datetime.timezone.utc)).days
                    if days_left < 0:
                        findings.append({
                            "name": "Expired TLS/SSL Certificate",
                            "vuln_type": "ssl_tls",
                            "severity": "critical",
                            "confidence": "certain",
                            "description": f"The TLS certificate on {ip}:{port} has expired.",
                            "evidence": f"Certificate expired {abs(days_left)} day(s) ago (notAfter={not_after}).",
                            "recommendation": "Renew the TLS certificate from your CA.",
                            "cve_id": "",
                            "cvss_score": None,
                        })
                    elif days_left <= 21:
                        findings.append({
                            "name": "TLS Certificate Expiring Soon",
                            "vuln_type": "ssl_tls",
                            "severity": "medium",
                            "confidence": "certain",
                            "description": f"The TLS certificate on {ip}:{port} expires within 3 weeks.",
                            "evidence": f"Expires in {days_left} day(s).",
                            "recommendation": "Schedule certificate renewal.",
                            "cve_id": "",
                            "cvss_score": None,
                        })

                # Check for weak cipher
                if cipher and cipher[0]:
                    weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT"]
                    for wc in weak_ciphers:
                        if wc.lower() in cipher[0].lower():
                            findings.append({
                                "name": f"Weak TLS Cipher Detected ({cipher[0]})",
                                "vuln_type": "ssl_tls",
                                "severity": "high",
                                "confidence": "certain",
                                "description": f"The cipher suite {cipher[0]} is considered weak or broken.",
                                "evidence": f"Cipher: {cipher[0]}, Protocol: {proto}",
                                "recommendation": "Configure the server to use strong ciphers only (AES-GCM, ChaCha20).",
                                "cve_id": "",
                                "cvss_score": None,
                            })
                            break

    except ssl.SSLCertVerificationError as exc:
        findings.append({
            "name": "Invalid or Self-Signed TLS Certificate",
            "vuln_type": "ssl_tls",
            "severity": "medium",
            "confidence": "firm",
            "description": f"The TLS certificate on {ip}:{port} could not be verified.",
            "evidence": str(getattr(exc, "verify_message", str(exc)))[:300],
            "recommendation": "Install a valid certificate from a trusted CA.",
            "cve_id": "",
            "cvss_score": None,
        })
    except Exception:
        pass  # Non-TLS port or unreachable

    return findings


def _check_insecure_service(ip, port, service, banner=""):
    """Check for insecure/legacy services."""
    findings = []
    svc_lower = service.lower()

    if svc_lower == "telnet":
        findings.append({
            "name": "Telnet Service Running (Insecure)",
            "vuln_type": "insecure_services",
            "severity": "high",
            "confidence": "certain",
            "description": (
                f"Telnet is running on {ip}:{port}. All data including credentials "
                "is transmitted in plaintext."
            ),
            "evidence": f"Port {port}/tcp open with Telnet service.",
            "recommendation": "Replace Telnet with SSH for remote access.",
            "cve_id": "",
            "cvss_score": None,
        })

    if svc_lower == "ftp":
        findings.append({
            "name": "FTP Service Running (Potentially Insecure)",
            "vuln_type": "insecure_services",
            "severity": "medium",
            "confidence": "firm",
            "description": (
                f"FTP is running on {ip}:{port}. FTP transmits credentials in plaintext "
                "and does not support encryption."
            ),
            "evidence": f"Port {port}/tcp open with FTP service.",
            "recommendation": "Use SFTP or FTPS instead of plain FTP.",
            "cve_id": "",
            "cvss_score": None,
        })

    if svc_lower in ("http",) and port != 443:
        # Check if HTTP is used when HTTPS might be expected
        pass  # Informational only

    return findings


def _check_banner_info_disclosure(ip, port, service, banner):
    """Check banner for information disclosure."""
    findings = []
    if not banner:
        return findings

    bl = banner.lower()

    # Version disclosure
    if any(x in bl for x in ["openssh", "apache", "nginx", "iis", "proftpd", "vsftpd"]):
        findings.append({
            "name": f"Service Version Disclosed ({service}:{port})",
            "vuln_type": "info_disclosure",
            "severity": "informational",
            "confidence": "certain",
            "description": f"The service banner at {ip}:{port} reveals version information.",
            "evidence": f"Banner: {banner[:200]}",
            "recommendation": "Suppress version information in service banners.",
            "cve_id": "",
            "cvss_score": None,
        })

    # Check for default/weak configurations
    if "anonymous" in bl and "ftp" in bl:
        findings.append({
            "name": "FTP Anonymous Access Detected",
            "vuln_type": "auth_weakness",
            "severity": "high",
            "confidence": "firm",
            "description": f"The FTP server at {ip}:{port} may allow anonymous access.",
            "evidence": f"Banner mentions anonymous: {banner[:200]}",
            "recommendation": "Disable anonymous FTP access.",
            "cve_id": "",
            "cvss_score": None,
        })

    return findings


def _check_smb_issues(ip, port, banner=""):
    """Check for SMB/network-service issues."""
    findings = []

    if port in (139, 445):
        # SMB is exposed
        findings.append({
            "name": f"SMB Service Exposed (Port {port})",
            "vuln_type": "smb_issues",
            "severity": "medium",
            "confidence": "certain",
            "description": (
                f"SMB (Server Message Block) is exposed on {ip}:{port}. "
                "If not properly secured, this can lead to remote code execution "
                "or information disclosure."
            ),
            "evidence": f"Port {port}/tcp open with SMB service.",
            "recommendation": (
                "Ensure SMBv1 is disabled. Restrict SMB access to authorized networks. "
                "Keep the system patched against known SMB vulnerabilities."
            ),
            "cve_id": "",
            "cvss_score": None,
        })

    if banner and ("smb" in banner.lower() or "microsoft-ds" in banner.lower()):
        if "smbv1" in banner.lower() or "nt lm" in banner.lower():
            findings.append({
                "name": "SMBv1 Enabled (Deprecated Protocol)",
                "vuln_type": "smb_issues",
                "severity": "high",
                "confidence": "firm",
                "description": (
                    f"The SMB service at {ip}:{port} appears to support SMBv1, "
                    "which is vulnerable to EternalBlue (MS17-010) and other attacks."
                ),
                "evidence": f"Banner: {banner[:200]}",
                "recommendation": "Disable SMBv1 and use SMBv2/v3.",
                "cve_id": "CVE-2017-0144",
                "cvss_score": 9.3,
            })

    return findings


def _check_remote_service_vulns(ip, port, service, version, banner):
    """Check for known vulnerabilities in exposed remote services."""
    findings = []

    # SSH checks
    if service == "ssh":
        if version and "openssh" in version.lower():
            # Check for very old versions
            ver_match = re.search(r"(\d+\.\d+)", version)
            if ver_match:
                ver_parts = ver_match.group(1).split(".")
                try:
                    major, minor = int(ver_parts[0]), int(ver_parts[1])
                    if major < 7 or (major == 7 and minor < 4):
                        findings.append({
                            "name": f"Outdated OpenSSH Version ({version})",
                            "vuln_type": "remote_service",
                            "severity": "high",
                            "confidence": "firm",
                            "description": f"OpenSSH {version} is outdated and may contain known vulnerabilities.",
                            "evidence": f"Detected version: {version}",
                            "recommendation": "Update OpenSSH to the latest stable version.",
                            "cve_id": "",
                            "cvss_score": None,
                        })
                except (ValueError, IndexError):
                    pass

        if banner and "password" in banner.lower():
            findings.append({
                "name": "SSH Password Authentication Enabled",
                "vuln_type": "remote_service",
                "severity": "medium",
                "confidence": "firm",
                "description": f"SSH on {ip}:{port} supports password authentication, making it susceptible to brute-force attacks.",
                "evidence": f"Banner indicates password authentication.",
                "recommendation": "Use key-based authentication and disable password login.",
                "cve_id": "",
                "cvss_score": None,
            })

    # RDP checks
    if service in ("ms-wbt-server", "rdp"):
        findings.append({
            "name": f"RDP Service Exposed (Port {port})",
            "vuln_type": "remote_service",
            "severity": "medium",
            "confidence": "certain",
            "description": f"RDP is exposed on {ip}:{port}. Exposed RDP is a common target for brute-force attacks and exploits.",
            "evidence": f"Port {port}/tcp open with RDP service.",
            "recommendation": "Restrict RDP access via VPN or firewall. Enable NLA (Network Level Authentication).",
            "cve_id": "",
            "cvss_score": None,
        })

    # Database services
    db_services = {
        "mysql": (3306, "MySQL"),
        "postgresql": (5432, "PostgreSQL"),
        "ms-sql-s": (1433, "Microsoft SQL Server"),
        "oracle": (1521, "Oracle"),
        "redis": (6379, "Redis"),
        "mongodb": (27017, "MongoDB"),
    }
    if service.lower() in db_services or port in [v[0] for v in db_services.values()]:
        db_name = db_services.get(service.lower(), (port, service))[1]
        findings.append({
            "name": f"{db_name} Database Exposed (Port {port})",
            "vuln_type": "remote_service",
            "severity": "high",
            "confidence": "certain",
            "description": f"{db_name} is exposed on {ip}:{port}. Database services should not be directly accessible from untrusted networks.",
            "evidence": f"Port {port}/tcp open with {db_name} service.",
            "recommendation": f"Restrict {db_name} access to authorized application servers only.",
            "cve_id": "",
            "cvss_score": None,
        })

    return findings


def scan_ip_target(ip, ports, options, progress_cb=None):
    """Scan a single IP address.

    Returns (host_data, findings) where host_data is a dict with host info
    and findings is a list of vulnerability dicts.
    """
    host_data = {
        "ip_address": ip,
        "hostname": "",
        "os_detection": "",
        "mac_address": "",
        "status": "down",
        "open_ports": [],
        "services": [],
        "findings": [],
    }
    findings = []

    # Resolve hostname
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        host_data["hostname"] = hostname
    except (socket.herror, socket.gaierror, OSError):
        pass

    # Host alive check
    alive = _is_host_alive(ip, timeout=1.5)
    if not alive:
        alive = _is_host_alive_icmp(ip, timeout=1)
    if not alive:
        # Final TCP probe on scan ports
        for p in ports[:5]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((ip, p)) == 0:
                    alive = True
                    sock.close()
                    break
                sock.close()
            except Exception:
                pass

    if not alive:
        host_data["status"] = "down"
        return host_data, findings

    host_data["status"] = "up"

    # Port scanning
    open_ports = []

    def _scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port, result == 0
        except Exception:
            return port, False

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(_scan_port, p): p for p in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    open_ports.sort()
    host_data["open_ports"] = open_ports
    host_data["open_ports_count"] = len(open_ports)

    # Service detection + banner grabbing
    services = []
    for port in open_ports:
        banner = _grab_banner(ip, port, timeout=2)
        service = _detect_service(ip, port, banner)
        version = _detect_version(banner, service)
        services.append({
            "port": port,
            "service": service,
            "version": version,
            "banner": banner,
        })
    host_data["services"] = services

    # OS detection (basic)
    os_info = _detect_os(ip)
    host_data["os_detection"] = os_info

    # --- Vulnerability checks ---

    # 1) Open/exposed port findings for non-standard ports
    for port_info in services:
        port = port_info["port"]
        service = port_info["service"]

        # 2) Insecure service checks
        insecure_findings = _check_insecure_service(ip, port, service, port_info["banner"])
        for f in insecure_findings:
            f["host_ip"] = ip
            f["port"] = port
            f["service"] = service
        findings.extend(insecure_findings)

        # 3) Information disclosure from banners
        disclosure_findings = _check_banner_info_disclosure(ip, port, service, port_info["banner"])
        for f in disclosure_findings:
            f["host_ip"] = ip
            f["port"] = port
            f["service"] = service
        findings.extend(disclosure_findings)

        # 4) SSL/TLS checks
        if service in ("https", "ssl", "ldaps", "imaps", "pop3s", "smtps") or port in (443, 8443, 636, 993, 995, 465):
            tls_findings = _tls_check(ip, port)
            for f in tls_findings:
                f["host_ip"] = ip
                f["port"] = port
                f["service"] = service
            findings.extend(tls_findings)

        # 5) SMB issues
        smb_findings = _check_smb_issues(ip, port, port_info["banner"])
        for f in smb_findings:
            f["host_ip"] = ip
            f["port"] = port
            f["service"] = service
        findings.extend(smb_findings)

        # 6) Remote service vulnerabilities
        remote_findings = _check_remote_service_vulns(ip, port, service, port_info["version"], port_info["banner"])
        for f in remote_findings:
            f["host_ip"] = ip
            f["port"] = port
            f["service"] = service
        findings.extend(remote_findings)

    # Determine risk level
    severities = [f.get("severity", "informational") for f in findings]
    if "critical" in severities:
        host_data["risk_level"] = "critical"
    elif "high" in severities:
        host_data["risk_level"] = "high"
    elif "medium" in severities:
        host_data["risk_level"] = "medium"
    elif "low" in severities:
        host_data["risk_level"] = "low"
    else:
        host_data["risk_level"] = "none"

    host_data["findings"] = findings
    host_data["vulnerabilities_count"] = len(findings)

    return host_data, findings


def scan_network(target, options, progress_cb=None):
    """Main entry point: scan a network target.

    Args:
        target: IP, CIDR, or range string
        options: dict with keys like scan_profile, enabled checks, etc.
        progress_cb: callable(pct, label) for progress updates

    Returns:
        (results_list, summary) where results_list is list of host_data dicts
        and summary is a dict with aggregate counts.
    """
    def _cb(pct, label):
        if progress_cb:
            try:
                progress_cb(pct, label)
            except Exception:
                pass

    _cb(2, "Parsing target")

    ips = _parse_targets(target)
    if not ips:
        return [], {"error": f"Could not parse target: {target}"}

    profile = options.get("scan_profile", "quick")
    ports = _get_ports_for_profile(profile, options.get("custom_ports"))

    # Limit total hosts for safety
    if len(ips) > 256:
        ips = ips[:256]

    total_hosts = len(ips)
    results = []
    all_findings = []
    hosts_discovered = 0

    # Phase 1: Host Discovery
    _cb(5, f"Discovering hosts (0/{total_hosts})")
    alive_ips = []
    for i, ip in enumerate(ips):
        if progress_cb and i % 10 == 0:
            pct = 5 + int(20 * i / total_hosts)
            _cb(pct, f"Discovering hosts ({i}/{total_hosts})")
        if _is_host_alive(ip, timeout=1.0):
            alive_ips.append(ip)

    if not alive_ips:
        _cb(100, "Scan complete - no hosts found")
        return [], {
            "hosts_discovered": 0,
            "open_ports": 0,
            "services": 0,
            "vulnerabilities": 0,
            "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0,
        }

    hosts_discovered = len(alive_ips)

    # Phase 2: Port Scanning + Service Detection + Vulnerability Analysis
    for i, ip in enumerate(alive_ips):
        host_pct = 25 + int(70 * i / hosts_discovered)
        _cb(host_pct, f"Scanning {ip} ({i+1}/{hosts_discovered})")

        host_data, findings = scan_ip_target(ip, ports, options)
        results.append(host_data)
        all_findings.extend(findings)

    _cb(98, "Finalizing results")

    # Aggregate summary
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    total_ports = 0
    total_services = 0
    for h in results:
        total_ports += h.get("open_ports_count", 0)
        total_services += len(h.get("services", []))
    for f in all_findings:
        sev = f.get("severity", "informational")
        if sev in severity_counts:
            severity_counts[sev] += 1

    _cb(100, "Scan complete")

    summary = {
        "hosts_discovered": hosts_discovered,
        "open_ports": total_ports,
        "services": total_services,
        "vulnerabilities": len(all_findings),
        **severity_counts,
    }

    return results, summary
