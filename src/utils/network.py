"""Auto-detect local network information (gateway, IP, subnet)."""

import ipaddress
import os
import platform
import re
import socket
import subprocess


def detect_network_info() -> dict:
    """Return detected network info with keys: gateway_ip, local_ip, subnet_cidr.

    Falls back to sensible defaults if detection fails.
    """
    gateway_ip = _detect_gateway()
    local_ip = _detect_local_ip()
    subnet_cidr = _detect_subnet(local_ip)

    return {
        "gateway_ip": gateway_ip or "192.168.1.1",
        "local_ip": local_ip or "127.0.0.1",
        "subnet_cidr": subnet_cidr or "192.168.1.0/24",
    }


def _detect_gateway() -> str:
    """Detect the default gateway IP address."""
    system = platform.system().lower()

    if system == "linux":
        gw = _gateway_from_proc_route()
        if gw:
            return gw

    if system == "windows":
        gw = _gateway_from_ipconfig()
        if gw:
            return gw

    # Fallback: try parsing `ip route` or `route` command output
    gw = _gateway_from_route_command()
    if gw:
        return gw

    return ""


def _gateway_from_proc_route() -> str:
    """Parse /proc/net/route to find the default gateway (Linux)."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    gw_hex = parts[2]
                    gw_bytes = bytes.fromhex(gw_hex)
                    return socket.inet_ntoa(gw_bytes)
    except (OSError, ValueError, IndexError):
        pass
    return ""


def _gateway_from_ipconfig() -> str:
    """Parse ipconfig output to find the default gateway (Windows)."""
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split("\n"):
            if "default gateway" in line.lower():
                match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    return match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return ""


def _gateway_from_route_command() -> str:
    """Try `ip route` or `route` commands as a fallback."""
    for cmd in [["ip", "route", "show", "default"], ["route", "-n"]]:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                match = re.search(r"(?:default\s+via\s+|0\.0\.0\.0\s+)(\d+\.\d+\.\d+\.\d+)", result.stdout)
                if match:
                    return match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
    return ""


def _detect_local_ip() -> str:
    """Detect the local IP address used for the default route."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        pass

    # Fallback: use hostname resolution
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.gaierror:
        pass

    return ""


def _detect_subnet(local_ip: str) -> str:
    """Detect the subnet CIDR for the given local IP."""
    if not local_ip or local_ip == "127.0.0.1":
        return ""

    # Try psutil if available (already a project dependency)
    prefix = _prefix_from_psutil(local_ip)
    if prefix:
        try:
            net = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
            return str(net)
        except ValueError:
            pass

    # Try parsing /proc/net/route for the local network route mask
    prefix = _prefix_from_proc_route(local_ip)
    if prefix:
        try:
            net = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
            return str(net)
        except ValueError:
            pass

    # Default to /24
    try:
        net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(net)
    except ValueError:
        return ""


def _prefix_from_psutil(local_ip: str) -> int:
    """Get prefix length from psutil network interface addresses."""
    try:
        import psutil
        for _iface, addr_list in psutil.net_if_addrs().items():
            for addr in addr_list:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    if addr.netmask:
                        mask_int = int(ipaddress.ip_address(addr.netmask))
                        return bin(mask_int).count("1")
    except (ImportError, OSError, ValueError):
        pass
    return 0


def _prefix_from_proc_route(local_ip: str) -> int:
    """Get prefix length from /proc/net/route for non-default routes."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 8 and parts[1] != "00000000":
                    mask_hex = parts[7]
                    mask_bytes = bytes.fromhex(mask_hex)
                    mask_int = int.from_bytes(mask_bytes, "little")
                    prefix = bin(mask_int).count("1")
                    if prefix > 0:
                        return prefix
    except (OSError, ValueError, IndexError):
        pass
    return 0


def is_admin() -> bool:
    """Check if the current process has administrator/root privileges."""
    system = platform.system().lower()
    if system == "windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except (ImportError, AttributeError, OSError):
            return False
    else:
        return os.geteuid() == 0
