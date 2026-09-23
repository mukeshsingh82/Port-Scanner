"""
scanner.py - TCP connect port scanning for Mini Port Scanner.

Standard library only and free of Qt imports, so the scanning logic stays
independent from the GUI in main.py.
"""

from __future__ import annotations

import errno
import ipaddress
import re
import socket
import threading
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from itertools import islice
from typing import Callable

MIN_PORT = 1
MAX_PORT = 65535
DEFAULT_TIMEOUT = 1.0      # seconds per connection attempt
MAX_WORKERS = 100          # concurrent connection attempts
FATAL_ERROR_LIMIT = 10     # abort after this many "unreachable / blocked" errors

STATE_OPEN = "OPEN"
STATE_CLOSED = "CLOSED"
STATE_FILTERED = "FILTERED"
STATE_ERROR = "ERROR"

# Fallback names used when the OS services database (/etc/services) has no entry.
COMMON_SERVICES: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    3000: "HTTP-Dev",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP-Alt",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9000: "HTTP-Alt",
    27017: "MongoDB",
}

# errno values meaning the host cannot be reached or connections are blocked.
FATAL_ERRNOS = {
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EHOSTDOWN,
    errno.ENETDOWN,
    errno.EACCES,
    errno.EPERM,
}

# A single DNS label: letters, digits, hyphens (underscores tolerated for LAN hosts).
_LABEL_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
# Linux network interface / zone identifier (e.g. eth0, wlan0, enp3s0, lo, or numeric scope id).
_ZONE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")

# getservbyport(3) is not thread-safe, so calls to it are serialized.
_services_lock = threading.Lock()


class ScanError(Exception):
    """Invalid input or a fatal problem that aborts a scan."""


@dataclass(frozen=True)
class ResolvedTarget:
    """A target that has been resolved via socket.getaddrinfo()."""

    host: str        # target as validated
    ip: str          # numeric IP (with %zone if present) for display
    family: int      # socket.AF_INET or socket.AF_INET6
    sockaddr: tuple  # getaddrinfo sockaddr: (ip, port) for IPv4 or (ip, port, flowinfo, scope_id) for IPv6

    def address(self, port: int) -> tuple:
        """Return the getaddrinfo() sockaddr tuple with the given TCP port."""
        return (self.sockaddr[0], port, *self.sockaddr[2:])


@dataclass(frozen=True)
class PortResult:
    """Outcome of probing a single port."""

    port: int
    state: str
    service: str = ""    # filled for open ports only
    detail: str = ""     # short description for FILTERED / ERROR results
    error_code: int = 0  # errno for ERROR results, 0 otherwise


ResultCallback = Callable[[PortResult], None]


def validate_target(target: str) -> str:
    """Return the cleaned target (IPv4, IPv6 with optional %zone, or hostname) or raise ScanError."""
    cleaned = target.strip()
    if not cleaned:
        raise ScanError("Enter a target IP address or hostname (for example 127.0.0.1, localhost, or ::1).")

    # Allow bracketed IPv6 literals such as [::1] or [fe80::1%eth0].
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()
        if not cleaned:
            raise ScanError("Enter a valid IPv6 address inside brackets (for example [::1]).")

    addr_part, sep, zone_part = cleaned.partition("%")
    try:
        ip_obj = ipaddress.ip_address(addr_part)
    except ValueError:
        ip_obj = None

    if ip_obj is not None:
        if sep:
            if not isinstance(ip_obj, ipaddress.IPv6Address):
                raise ScanError(f"Zone identifier '%{zone_part}' is only valid with IPv6 addresses.")
            if not zone_part or not _ZONE_RE.match(zone_part):
                raise ScanError(
                    f"Invalid IPv6 zone/interface identifier '%{zone_part}' in '{cleaned}' "
                    "(example: fe80::1%eth0)."
                )
            return f"{ip_obj.compressed}%{zone_part}"
        return ip_obj.compressed

    # If it contains ':' or '%', the user intended an IPv6 literal that is malformed.
    if ":" in cleaned or sep:
        raise ScanError(f"'{target.strip()}' is not a valid IPv6 address.")

    hostname = cleaned.rstrip(".")
    if 0 < len(hostname) <= 253 and all(_LABEL_RE.match(label) for label in hostname.split(".")):
        return cleaned
    raise ScanError(f"'{target.strip()}' is not a valid IP address or hostname.")


def validate_port_range(start_port: int, end_port: int) -> tuple[int, int]:
    """Return (start_port, end_port) or raise ScanError if the range is invalid."""
    for name, value in (("Start port", start_port), ("End port", end_port)):
        if not MIN_PORT <= value <= MAX_PORT:
            raise ScanError(f"{name} must be between {MIN_PORT} and {MAX_PORT}.")
    if start_port > end_port:
        raise ScanError("Start port must be less than or equal to end port.")
    return start_port, end_port


def _has_local_route(family: int, sockaddr: tuple) -> bool:
    """Fast kernel route check using a UDP socket (sends no packets on the network)."""
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as probe:
            probe.connect((sockaddr[0], 80, *sockaddr[2:]))
        return True
    except OSError:
        return False


def _resolve_zone_scope_id(zone: str, host: str) -> int:
    """Convert a Linux interface name (e.g. 'eth0') or numeric scope ID to an integer scope_id."""
    if zone.isdigit():
        return int(zone)
    try:
        return socket.if_nametoindex(zone)
    except OSError as exc:
        raise ScanError(
            f"Unknown network interface '{zone}' in IPv6 target '{host}'. "
            "Use a valid local interface name (for example fe80::1%eth0)."
        ) from exc


def resolve_target(host: str) -> ResolvedTarget:
    """
    Resolve an IPv4 address, IPv6 address (including %interface), or hostname
    using socket.getaddrinfo() and select socket.AF_INET or socket.AF_INET6.
    """
    host = validate_target(host)
    addr_part, sep, zone_part = host.partition("%")

    # Check link-local IPv6 without a zone identifier early so Linux users get a clear message.
    try:
        parsed_ip = ipaddress.ip_address(addr_part)
    except ValueError:
        parsed_ip = None

    if isinstance(parsed_ip, ipaddress.IPv6Address) and parsed_ip.is_link_local and not sep:
        raise ScanError(
            f"Link-local IPv6 address '{host}' requires a zone/interface identifier on Linux "
            f"(for example: {host}%eth0)."
        )

    # Validate the interface name up front if a zone identifier was supplied.
    explicit_scope_id = _resolve_zone_scope_id(zone_part, host) if sep else 0

    try:
        infos = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
            flags=0,
        )
    except socket.gaierror as exc:
        if exc.errno in (getattr(socket, "EAI_ADDRFAMILY", -9), getattr(socket, "EAI_NODATA", -5)) and isinstance(
            parsed_ip, ipaddress.IPv6Address
        ):
            raise ScanError(
                f"Network is unreachable: the local system currently has no reachable IPv6 route "
                f"or interface for '{host}'."
            ) from exc
        raise ScanError(f"Could not resolve '{host}': {exc.strerror or exc}") from exc
    except OSError as exc:
        if exc.errno == errno.ENETUNREACH and isinstance(parsed_ip, ipaddress.IPv6Address):
            raise ScanError(
                f"Network is unreachable: the local system currently has no reachable IPv6 route "
                f"or interface for '{host}'."
            ) from exc
        raise ScanError(f"Could not resolve '{host}': {exc.strerror or exc}") from exc

    candidates = [info for info in infos if info[0] in (socket.AF_INET, socket.AF_INET6)]
    if not candidates:
        raise ScanError(f"Could not resolve '{host}' to an IPv4 or IPv6 address.")

    # When a hostname resolves to multiple addresses (e.g. localhost -> ::1 and 127.0.0.1),
    # prefer an address with an active local route, and prefer IPv4 when both are reachable.
    if len(candidates) > 1:
        candidates.sort(
            key=lambda info: (
                not _has_local_route(info[0], info[4]),
                info[0] != socket.AF_INET,
            )
        )

    family, _, _, _, sockaddr = candidates[0]
    if family == socket.AF_INET6:
        flowinfo = sockaddr[2] if len(sockaddr) > 2 else 0
        scope_id = sockaddr[3] if len(sockaddr) > 3 else 0
        if explicit_scope_id and scope_id == 0:
            scope_id = explicit_scope_id
        sockaddr = (sockaddr[0], 0, flowinfo, scope_id)
        display_ip = f"{sockaddr[0]}%{zone_part}" if sep and "%" not in sockaddr[0] else sockaddr[0]
    else:
        sockaddr = (sockaddr[0], 0)
        display_ip = sockaddr[0]

    return ResolvedTarget(host=host, ip=display_ip, family=family, sockaddr=sockaddr)


def get_service_name(port: int) -> str:
    """Service name from the OS services database, then the fallback table."""
    with _services_lock:
        try:
            name = socket.getservbyport(port, "tcp")
        except OSError:
            return COMMON_SERVICES.get(port, "Unknown")
    return name.upper()


def _format_connect_error(target: ResolvedTarget, code: int, fallback: str) -> str:
    """Human-friendly description for socket connect errors, especially IPv6 route issues."""
    if code == errno.ENETUNREACH:
        if target.family == socket.AF_INET6:
            return (
                "Network is unreachable: the local system currently has no reachable IPv6 route "
                f"or interface for {target.ip}"
            )
        return f"Network is unreachable: no local route or interface to reach {target.ip}"
    if code == errno.EADDRNOTAVAIL and target.family == socket.AF_INET6:
        return f"Cannot assign requested IPv6 address for {target.ip} (check interface/scope)"
    return fallback


def scan_port(target: ResolvedTarget, port: int, timeout: float = DEFAULT_TIMEOUT) -> PortResult:
    """
    TCP connect probe of one port using target.family (AF_INET or AF_INET6)
    and the sockaddr returned by getaddrinfo(). Never raises for network problems.
    """
    try:
        with socket.socket(target.family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(target.address(port))
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError):
        return PortResult(port, STATE_CLOSED)
    except TimeoutError:
        return PortResult(port, STATE_FILTERED, detail="Connection timed out")
    except PermissionError as exc:
        return PortResult(port, STATE_ERROR, detail="Permission denied", error_code=exc.errno or errno.EACCES)
    except OSError as exc:
        code = exc.errno or 0
        # Normal closed or timed-out ports must never be treated as fatal scan errors.
        if code in (errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED):
            return PortResult(port, STATE_CLOSED)
        if code == errno.ETIMEDOUT:
            return PortResult(port, STATE_FILTERED, detail="Connection timed out")
        detail = _format_connect_error(target, code, exc.strerror or str(exc))
        return PortResult(port, STATE_ERROR, detail=detail, error_code=code)
    return PortResult(port, STATE_OPEN, service=get_service_name(port))


def scan_ports(
    target: ResolvedTarget,
    start_port: int,
    end_port: int,
    on_result: ResultCallback,
    stop_event: threading.Event | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = MAX_WORKERS,
) -> None:
    """
    Probe every port in [start_port, end_port] and call on_result(PortResult)
    for each one, in completion order (not port order).

    Individual closed, refused, timed-out, or isolated unreachable ports never
    abort the scan. Aborts with ScanError only after FATAL_ERROR_LIMIT (10)
    consecutive fatal network errors (e.g. host/network unreachable).
    """
    stop_event = stop_event or threading.Event()
    ports = iter(range(start_port, end_port + 1))
    window = max_workers * 2  # bounded queue keeps memory low and Stop responsive
    in_flight: set[Future] = set()
    fatal_errors = 0

    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="portscan") as pool:
        try:
            while not stop_event.is_set():
                for port in islice(ports, window - len(in_flight)):
                    in_flight.add(pool.submit(scan_port, target, port, timeout))
                if not in_flight:
                    break  # every port has been submitted and reported

                done, in_flight = wait(in_flight, timeout=0.25, return_when=FIRST_COMPLETED)
                for future in done:
                    result = future.result()
                    on_result(result)
                    if result.state in (STATE_OPEN, STATE_CLOSED):
                        # Host responded with SYN-ACK or RST: it is reachable.
                        fatal_errors = 0
                    elif result.state == STATE_ERROR and result.error_code in FATAL_ERRNOS:
                        fatal_errors += 1
                        if fatal_errors >= FATAL_ERROR_LIMIT:
                            if result.error_code == errno.ENETUNREACH and target.family == socket.AF_INET6:
                                raise ScanError(
                                    "Network is unreachable: the local system currently has no "
                                    f"reachable IPv6 route or interface to scan {target.ip} "
                                    f"(aborted after {fatal_errors} failed connection attempts)."
                                )
                            if result.error_code == errno.ENETUNREACH:
                                raise ScanError(
                                    "Network is unreachable: the local system currently has no "
                                    f"route or interface to reach {target.ip} "
                                    f"(aborted after {fatal_errors} failed connection attempts)."
                                )
                            raise ScanError(
                                f"Scan aborted after {fatal_errors} failed connections "
                                f"({result.detail}). Host {target.ip} is unreachable or "
                                "connections are being blocked."
                            )
        finally:
            for future in in_flight:
                future.cancel()
