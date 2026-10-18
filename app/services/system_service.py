import platform
import socket
import os
import sys
import ctypes
import shutil
import subprocess
from typing import Dict, List, Optional, Any

# ============================================================
# WINDOWS INSTALLED APPLICATIONS COLLECTOR
# ============================================================

def collect_windows_applications() -> dict:
    """
    Discovers installed applications from the Windows Registry in read-only mode.
    Queries HKLM and HKCU Uninstall keys.
    """
    if sys.platform != "win32":
        return {
            "status": "UNAVAILABLE",
            "coverage": "Windows Registry interface (winreg) unavailable on this system",
            "applications": []
        }

    import winreg

    registry_targets = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "Windows Registry (HKLM)"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "Windows Registry (HKLM-Wow6432)"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", "Windows Registry (HKCU)")
    ]

    apps = []
    sources_used = set()
    seen = set()

    for hkey_root, subkey_path, source_name in registry_targets:
        try:
            with winreg.OpenKey(hkey_root, subkey_path, 0, winreg.KEY_READ) as key:
                sources_used.add(source_name)
                num_subkeys, _, _ = winreg.QueryInfoKey(key)
                for i in range(num_subkeys):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ) as app_key:
                            # Skip system components
                            try:
                                is_sys, _ = winreg.QueryValueEx(app_key, "SystemComponent")
                                if is_sys == 1:
                                    continue
                            except OSError:
                                pass

                            # Skip updates / patches with parent keys
                            try:
                                parent, _ = winreg.QueryValueEx(app_key, "ParentKeyName")
                                if parent:
                                    continue
                            except OSError:
                                pass

                            # Get DisplayName
                            try:
                                display_name, _ = winreg.QueryValueEx(app_key, "DisplayName")
                                display_name = str(display_name).strip() if display_name else ""
                            except OSError:
                                display_name = ""

                            if not display_name:
                                continue

                            # Get DisplayVersion if available
                            try:
                                display_version, _ = winreg.QueryValueEx(app_key, "DisplayVersion")
                                display_version = str(display_version).strip() if display_version else None
                            except OSError:
                                display_version = None

                            dedup_key = (display_name.lower(), (display_version or "").lower())
                            if dedup_key in seen:
                                continue
                            seen.add(dedup_key)

                            apps.append({
                                "name": display_name,
                                "version": display_version,
                                "source": "Windows Registry"
                            })
                    except OSError:
                        continue
        except OSError:
            # Key does not exist or cannot be opened
            pass

    if apps:
        return {
            "status": "SUCCESS",
            "coverage": "Installed applications detected from Windows Registry",
            "applications": apps
        }
    elif sources_used:
        return {
            "status": "SUCCESS",
            "coverage": "Windows Registry queried; no applications found",
            "applications": []
        }
    else:
        return {
            "status": "UNAVAILABLE",
            "coverage": "Windows Registry Uninstall keys inaccessible",
            "applications": []
        }


# ============================================================
# LINUX INSTALLED APPLICATIONS COLLECTORS
# ============================================================

def _collect_rpm() -> Optional[List[Dict[str, Any]]]:
    """Collects installed RPM packages using rpm -qa."""
    rpm_path = shutil.which("rpm")
    if not rpm_path:
        return None
    try:
        proc = subprocess.run(
            [rpm_path, "-qa", "--queryformat", "%{NAME}|%{VERSION}\n"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode != 0:
            return None
        apps = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            name, version = line.split("|", 1)
            name = name.strip()
            version = version.strip()
            if not name:
                continue
            if not version or version == "(none)":
                version = None
            apps.append({"name": name, "version": version, "source": "rpm"})
        return apps
    except (subprocess.TimeoutExpired, OSError):
        return None


def _collect_dpkg() -> Optional[List[Dict[str, Any]]]:
    """Collects installed DPKG packages using dpkg-query."""
    dpkg_path = shutil.which("dpkg-query")
    if not dpkg_path:
        return None
    try:
        proc = subprocess.run(
            [dpkg_path, "-W", "-f=${Package}|${Version}\n"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode != 0:
            return None
        apps = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line or "|" not in line:
                continue
            name, version = line.split("|", 1)
            name = name.strip()
            version = version.strip()
            if not name:
                continue
            if not version:
                version = None
            apps.append({"name": name, "version": version, "source": "dpkg"})
        return apps if apps else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def _collect_pacman() -> Optional[List[Dict[str, Any]]]:
    """Collects installed Pacman packages using pacman -Q."""
    pacman_path = shutil.which("pacman")
    if not pacman_path:
        return None
    try:
        proc = subprocess.run(
            [pacman_path, "-Q"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode != 0:
            return None
        apps = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            name = parts[0].strip()
            version = parts[1].strip() if len(parts) > 1 else None
            if not name:
                continue
            apps.append({"name": name, "version": version, "source": "pacman"})
        return apps if apps else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def _collect_flatpak() -> Optional[List[Dict[str, Any]]]:
    """Collects installed Flatpak applications using flatpak list --app."""
    flatpak_path = shutil.which("flatpak")
    if not flatpak_path:
        return None
    try:
        proc = subprocess.run(
            [flatpak_path, "list", "--app", "--columns=name,version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode != 0:
            return None
        apps = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t")
            name = parts[0].strip()
            version = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
            if not name:
                continue
            apps.append({"name": name, "version": version, "source": "flatpak"})
        return apps
    except (subprocess.TimeoutExpired, OSError):
        return None


def _collect_snap() -> Optional[List[Dict[str, Any]]]:
    """Collects installed Snap packages using snap list."""
    snap_path = shutil.which("snap")
    if not snap_path:
        return None
    try:
        proc = subprocess.run(
            [snap_path, "list"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode != 0:
            return None
        apps = []
        lines = proc.stdout.splitlines()
        if len(lines) > 1:
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0].strip()
                    version = parts[1].strip()
                    if name:
                        apps.append({"name": name, "version": version, "source": "snap"})
        return apps
    except (subprocess.TimeoutExpired, OSError):
        return None


def _collect_desktop_entries() -> Optional[List[Dict[str, Any]]]:
    """Fallback: read .desktop files from /usr/share/applications/ if no package managers found."""
    app_dir = "/usr/share/applications"
    if not os.path.isdir(app_dir):
        return None
    apps = []
    try:
        for entry in os.listdir(app_dir):
            if entry.endswith(".desktop"):
                path = os.path.join(app_dir, entry)
                name = None
                version = None
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.startswith("Name=") and not name:
                                name = line.split("=", 1)[1].strip()
                            elif line.startswith("Version=") and not version:
                                version = line.split("=", 1)[1].strip()
                            if name and version:
                                break
                    if name:
                        apps.append({"name": name, "version": version, "source": "Desktop Entries"})
                except OSError:
                    continue
        return apps if apps else None
    except OSError:
        return None


def collect_linux_applications() -> dict:
    """
    Discovers installed applications on Linux using available local package managers:
    RPM, DPKG, Pacman, Flatpak, Snap, with fallback to XDG desktop files.
    Deduplicates deterministically without silently removing different versions.
    """
    all_apps = []
    active_sources = []

    # 1. Primary system package managers
    rpm_apps = _collect_rpm()
    if rpm_apps is not None:
        all_apps.extend(rpm_apps)
        active_sources.append("RPM package database")

    dpkg_apps = _collect_dpkg()
    if dpkg_apps is not None:
        all_apps.extend(dpkg_apps)
        active_sources.append("DPKG package database")

    pacman_apps = _collect_pacman()
    if pacman_apps is not None:
        all_apps.extend(pacman_apps)
        active_sources.append("Pacman package database")

    # 2. Universal / sandbox package managers
    flatpak_apps = _collect_flatpak()
    if flatpak_apps is not None:
        all_apps.extend(flatpak_apps)
        active_sources.append("Flatpak")

    snap_apps = _collect_snap()
    if snap_apps is not None:
        all_apps.extend(snap_apps)
        active_sources.append("Snap")

    # 3. Fallback to desktop entries only if no package managers yielded apps
    if not all_apps:
        desktop_apps = _collect_desktop_entries()
        if desktop_apps is not None:
            all_apps.extend(desktop_apps)
            active_sources.append("Desktop Entries")

    if not active_sources:
        return {
            "status": "UNAVAILABLE",
            "coverage": "No supported Linux package managers (RPM, DPKG, Pacman, Flatpak, Snap) available",
            "applications": []
        }

    # Deterministic deduplication:
    # Avoid exact duplicate records for identical (name, version)
    # Do not silently remove distinct applications with different versions.
    seen = set()
    deduped = []
    for app in all_apps:
        name_clean = app["name"].strip()
        ver_clean = (app.get("version") or "").strip()
        key = (name_clean.lower(), ver_clean.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(app)

    coverage_str = f"Installed applications detected from {', '.join(active_sources)}"
    return {
        "status": "SUCCESS",
        "coverage": coverage_str,
        "applications": deduped
    }


def get_installed_applications() -> dict:
    """
    Platform router for discovering installed applications.
    Supports Linux and Windows. Isolates platform-specific logic.
    """
    sys_os = platform.system()
    if sys_os == "Linux":
        return collect_linux_applications()
    elif sys_os == "Windows":
        return collect_windows_applications()
    else:
        return {
            "status": "UNAVAILABLE",
            "coverage": f"Installed application collection is not supported on {sys_os}",
            "applications": []
        }


# ============================================================
# RUNNING PROCESSES COLLECTOR
# ============================================================

def _collect_windows_processes_toolhelp() -> dict:
    """Fallback collector using Win32 Toolhelp32 snapshot (fast & no external processes)."""
    try:
        from ctypes import wintypes

        class PROCESSENTRY32(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_char * 260)
            ]

        # TH32CS_SNAPPROCESS = 0x00000002
        h_snap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if h_snap == -1 or h_snap == 0:
            return {"status": "UNAVAILABLE", "processes": []}

        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

        processes = []
        if ctypes.windll.kernel32.Process32First(h_snap, ctypes.byref(pe)):
            while True:
                name = pe.szExeFile.decode("utf-8", errors="replace").rstrip("\x00")
                pid = str(pe.th32ProcessID)
                if name:
                    processes.append({
                        "pid": pid,
                        "name": name,
                        "executable": "Unavailable",
                        "user": "Unavailable",
                        "status": "Running"
                    })
                if not ctypes.windll.kernel32.Process32Next(h_snap, ctypes.byref(pe)):
                    break

        ctypes.windll.kernel32.CloseHandle(h_snap)
        if processes:
            return {"status": "SUCCESS", "processes": processes}
        return {"status": "UNAVAILABLE", "processes": []}
    except Exception:
        return {"status": "UNAVAILABLE", "processes": []}


def collect_windows_processes() -> dict:
    """Collect running processes on Windows using tasklist with Toolhelp fallback."""
    try:
        proc = subprocess.run(
            ["tasklist", "/FO", "CSV"],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode == 0 and proc.stdout:
            processes = []
            import csv
            import io
            reader = csv.DictReader(io.StringIO(proc.stdout))
            for row in reader:
                pid = row.get("PID", "").strip()
                name = row.get("Image Name", "").strip()
                if not pid or not name:
                    continue

                user_raw = row.get("User Name", "").strip()
                status_raw = row.get("Status")

                user = user_raw if user_raw and user_raw != "N/A" else "Unavailable"

                if status_raw is not None:
                    status_str = status_raw.strip()
                    status = status_str if status_str and status_str != "Unknown" else "Unavailable"
                else:
                    status = "Running"

                processes.append({
                    "pid": pid,
                    "name": name,
                    "executable": "Unavailable",
                    "user": user,
                    "status": status
                })

            if processes:
                return {"status": "SUCCESS", "processes": processes}
    except Exception:
        pass

    # Fallback to Toolhelp32 snapshot if tasklist timed out, failed, or was unavailable
    try:
        return _collect_windows_processes_toolhelp()
    except Exception:
        return {"status": "UNAVAILABLE", "processes": []}


def collect_linux_processes() -> dict:
    """Collect running processes on Linux using ps and /proc."""
    ps_path = shutil.which("ps")
    if not ps_path:
        return {"status": "UNAVAILABLE", "processes": []}
        
    try:
        proc = subprocess.run(
            [ps_path, "-e", "-o", "pid=,user=,stat=,comm="],
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        if proc.returncode != 0:
            return {"status": "UNAVAILABLE", "processes": []}
            
        processes = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
                
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
                
            pid_str = parts[0]
            user = parts[1]
            status = parts[2]
            name = parts[3]
            
            executable = "Unavailable"
            try:
                exe_path = os.readlink(f"/proc/{pid_str}/exe")
                if exe_path:
                    executable = exe_path
            except OSError:
                pass
                
            processes.append({
                "pid": pid_str,
                "name": name,
                "executable": executable,
                "user": user,
                "status": status
            })
            
        return {"status": "SUCCESS", "processes": processes}
    except Exception:
        return {"status": "UNAVAILABLE", "processes": []}


def get_running_processes() -> dict:
    """
    Platform router for discovering running processes.
    Supports Linux and Windows.
    """
    sys_os = platform.system()
    if sys_os == "Linux":
        return collect_linux_processes()
    elif sys_os == "Windows":
        return collect_windows_processes()
    else:
        return {
            "status": "UNAVAILABLE",
            "processes": []
        }


# ============================================================
# STARTUP APPLICATIONS COLLECTOR
# ============================================================

def collect_windows_startup() -> dict:
    """Collects startup applications on Windows."""
    if sys.platform != "win32":
        return {"status": "UNAVAILABLE", "coverage": "Windows specific", "applications": []}
    
    import winreg
    import os
    
    apps = []
    sources_used = set()
    
    # 1. Registry Run Keys
    registry_targets = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "System", "Windows Registry Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "User", "Windows Registry Run")
    ]
    
    for hkey, subkey, scope, source in registry_targets:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                sources_used.add(source)
                _, num_values, _ = winreg.QueryInfoKey(key)
                for i in range(num_values):
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        name = name.strip()
                        value = str(value).strip() if value else ""
                        if name:
                            apps.append({
                                "name": name,
                                "source": source,
                                "scope": scope,
                                "command": value,
                                "enabled": "Unknown" # Registry entries are generally enabled if present
                            })
                    except OSError:
                        continue
        except OSError:
            pass

    # 2. Startup Folders
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("ALLUSERSPROFILE")
    
    folder_targets = []
    if programdata:
        folder_targets.append((os.path.join(programdata, r"Microsoft\Windows\Start Menu\Programs\StartUp"), "System", "Windows Startup Folder"))
    if appdata:
        folder_targets.append((os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"), "User", "Windows Startup Folder"))
        
    for folder_path, scope, source in folder_targets:
        if not folder_path or not os.path.isdir(folder_path):
            continue
        sources_used.add(source)
        try:
            for entry in os.listdir(folder_path):
                if entry.lower() == "desktop.ini":
                    continue
                apps.append({
                    "name": entry,
                    "source": source,
                    "scope": scope,
                    "command": "Unavailable (Shortcut file)",
                    "enabled": "Unknown"
                })
        except OSError:
            pass

    # Deterministic Deduplication for Windows apps
    seen = set()
    deduped = []
    for app in apps:
        key = (app["name"].strip().lower(), app["scope"], app["source"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(app)

    if deduped:
        return {
            "status": "SUCCESS",
            "coverage": "Startup applications detected from Run registry keys and Startup folders.",
            "applications": deduped
        }
    elif sources_used:
        return {
            "status": "SUCCESS",
            "coverage": "Queried Run registry keys and Startup folders; no startup applications found.",
            "applications": []
        }
    else:
        return {
            "status": "UNAVAILABLE",
            "coverage": "Windows startup sources inaccessible.",
            "applications": []
        }


def _parse_desktop_file(path: str) -> Optional[Dict[str, Any]]:
    name = None
    exec_cmd = None
    enabled = "True"
    
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("Name=") and not name:
                    name = line.split("=", 1)[1].strip()
                elif line.startswith("Exec=") and not exec_cmd:
                    exec_cmd = line.split("=", 1)[1].strip()
                elif line.startswith("X-GNOME-Autostart-enabled="):
                    val = line.split("=", 1)[1].strip().lower()
                    if val == "false":
                        enabled = "False"
                elif line.startswith("Hidden="):
                    val = line.split("=", 1)[1].strip().lower()
                    if val == "true":
                        enabled = "False"
    except OSError:
        return None
        
    if name:
        return {
            "name": name,
            "command": exec_cmd if exec_cmd else "Unavailable",
            "enabled": enabled
        }
    return None


def collect_linux_startup() -> dict:
    """Collects startup applications on Linux from XDG autostart."""
    import os
    apps = []
    sources_used = set()
    
    targets = [
        ("/etc/xdg/autostart", "System", "Linux XDG Autostart"),
        (os.path.expanduser("~/.config/autostart"), "User", "Linux XDG Autostart")
    ]
    
    for path, scope, source in targets:
        if os.path.isdir(path):
            sources_used.add(source)
            try:
                for entry in os.listdir(path):
                    if entry.endswith(".desktop"):
                        full_path = os.path.join(path, entry)
                        parsed = _parse_desktop_file(full_path)
                        if parsed:
                            apps.append({
                                "name": parsed["name"],
                                "source": source,
                                "scope": scope,
                                "command": parsed["command"],
                                "enabled": parsed["enabled"]
                            })
            except OSError:
                pass
                
    # Deterministic Deduplication for Linux apps
    seen = set()
    deduped = []
    for app in apps:
        key = (app["name"].strip().lower(), app["scope"], app["source"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(app)

    if deduped:
        return {
            "status": "SUCCESS",
            "coverage": "Startup applications detected from XDG autostart sources.",
            "applications": deduped
        }
    elif sources_used:
        return {
            "status": "SUCCESS",
            "coverage": "Queried XDG autostart sources; no startup applications found.",
            "applications": []
        }
    else:
        return {
            "status": "UNAVAILABLE",
            "coverage": "Linux XDG autostart directories inaccessible or missing.",
            "applications": []
        }


def get_startup_applications() -> dict:
    """Platform router for discovering startup applications."""
    sys_os = platform.system()
    if sys_os == "Linux":
        return collect_linux_startup()
    elif sys_os == "Windows":
        return collect_windows_startup()
    else:
        return {
            "status": "UNAVAILABLE",
            "coverage": f"Startup application collection is not supported on {sys_os}",
            "applications": []
        }


# ============================================================
# SYSTEM FOOTPRINT SCANNER
# ============================================================

async def check_system() -> dict:
    """
    Collects basic read-only system footprint information including installed applications.
    Must support Windows and Linux using standard libraries.
    """
    results = {}
    
    # 1. Operating System
    sys_os = platform.system()
    results['os'] = sys_os if sys_os else "Unknown"

    # 2. OS Version
    try:
        if sys_os == "Linux":
            # Prefer freedesktop os-release if available for a readable name
            try:
                with open("/etc/os-release") as f:
                    lines = f.readlines()
                    pretty_name = next((line.split("=")[1].strip().strip('"') for line in lines if line.startswith("PRETTY_NAME=")), None)
                    results['os_version'] = pretty_name if pretty_name else f"{platform.release()} ({platform.version()})"
            except Exception:
                results['os_version'] = f"{platform.release()} ({platform.version()})"
        else:
            results['os_version'] = f"{platform.release()} ({platform.version()})"
    except Exception:
        results['os_version'] = "Unavailable"

    # 3. Hostname
    try:
        results['hostname'] = socket.gethostname()
    except Exception:
        results['hostname'] = "Unavailable"

    # 4. CPU Information
    try:
        processor = platform.processor()
        count = os.cpu_count()
        results['cpu'] = f"{processor} ({count} Logical Cores)" if processor else f"Unknown Processor ({count} Logical Cores)"
    except Exception:
        results['cpu'] = "Unavailable"

    # 5. Memory Information
    memory_str = "Unavailable"
    try:
        if sys_os == "Linux":
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    if line.startswith('MemTotal:'):
                        mem_kb = int(line.split()[1])
                        mem_gb = mem_kb / (1024 ** 2)
                        memory_str = f"{mem_gb:.2f} GB"
                        break
        elif sys_os == "Windows":
            if sys.platform == "win32":
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]
                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
                mem_gb = stat.ullTotalPhys / (1024 ** 3)
                memory_str = f"{mem_gb:.2f} GB"
            else:
                memory_str = "Unavailable"
    except Exception:
        memory_str = "Unavailable"
    
    results['memory'] = memory_str

    # 6. Basic Network Information
    try:
        hostname = socket.gethostname()
        _, _, ip_addresses = socket.gethostbyname_ex(hostname)
        # Filter out loopback if possible, but keeping it simple
        ips = [ip for ip in ip_addresses if not ip.startswith("127.")]
        if not ips and ip_addresses:
            ips = ip_addresses
        results['network'] = ", ".join(ips) if ips else "Unavailable"
    except Exception:
        results['network'] = "Unavailable"

    # 7. Installed Applications
    try:
        app_res = get_installed_applications()
        results['installed_applications'] = app_res.get('applications', [])
        results['installed_applications_status'] = app_res.get('status', 'UNAVAILABLE')
        results['installed_applications_coverage'] = app_res.get('coverage', '')
    except Exception as e:
        results['installed_applications'] = []
        results['installed_applications_status'] = 'UNAVAILABLE'
        results['installed_applications_coverage'] = f"Error discovering applications: {str(e)}"

    # 8. Running Processes
    try:
        proc_res = get_running_processes()
        results['running_processes'] = proc_res.get('processes', [])
        results['running_processes_status'] = proc_res.get('status', 'UNAVAILABLE')
    except Exception:
        results['running_processes'] = []
        results['running_processes_status'] = 'UNAVAILABLE'

    # 9. Startup Applications
    try:
        startup_res = get_startup_applications()
        results['startup_applications'] = startup_res.get('applications', [])
        results['startup_applications_status'] = startup_res.get('status', 'UNAVAILABLE')
        results['startup_applications_coverage'] = startup_res.get('coverage', '')
    except Exception as e:
        results['startup_applications'] = []
        results['startup_applications_status'] = 'UNAVAILABLE'
        results['startup_applications_coverage'] = f"Error discovering startup applications: {str(e)}"

    return {
        "status": "SUCCESS",
        "results": results
    }
