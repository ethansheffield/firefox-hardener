#!/usr/bin/env python3
"""
Firefox Hardener - Security-focused Firefox installer and configurator
Designed for privacy-conscious users and Tails OS compatibility
"""

import os
import sys
import json
import shutil
import re
import argparse
import subprocess
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

# Helper class for terminal colors
class Colors:
    """A simple class to hold ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'


def visible_len(s: str) -> int:
    """Calculates the visible length of a string, ignoring ANSI color codes."""
    return len(re.sub(r'\033\[\d+m', '', s))


class FirefoxHardener:
    """Main class for Firefox hardening using a hybrid policy and profile management approach."""

    VERSION = "2.6.0"

    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.backup_dir = self.base_dir / "backups"
        self.backup_dir.mkdir(exist_ok=True)
        self.system = sys.platform
        self.is_linux = self.system.startswith('linux')
        self.is_mac = self.system == 'darwin'
        self.is_windows = self.system.startswith('win')

        self.extensions = {
            "ublock_origin": { "name": "uBlock Origin", "url": "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi", "id": "uBlock0@raymondhill.net" },
            "multi_account_containers": { "name": "Multi-Account Containers", "url": "https://addons.mozilla.org/firefox/downloads/latest/multi-account-containers/latest.xpi", "id": "@testpilot-containers" },
            "temporary_containers": { "name": "Temporary Containers", "url": "https://addons.mozilla.org/firefox/downloads/latest/temporary-containers/latest.xpi", "id": "{c607c8df-14a7-4f28-894f-29e8722976af}" },
            "localcdn": { "name": "LocalCDN", "url": "https://addons.mozilla.org/firefox/downloads/latest/localcdn-fork-of-decentraleyes/latest.xpi", "id": "{b86e4813-687a-43e6-ab65-0bde4ab75758}" },
            "clearurls": { "name": "ClearURLs", "url": "https://addons.mozilla.org/firefox/downloads/latest/clearurls/latest.xpi", "id": "{74145f27-f039-47ce-a470-a662b129930a}" },
            "canvasblocker": { "name": "CanvasBlocker", "url": "https://addons.mozilla.org/firefox/downloads/latest/canvasblocker/latest.xpi", "id": "CanvasBlocker@kkapsner.de" }
        }

    def display_header(self):
        """Displays the application's title header, centered for 80-column terminals."""
        c = Colors
        terminal_width = 80

        logo_raw = r"""
____________/\\\________/\\\\\\\________/\\\\\\\\\\__
 __________ /\\\\\______/\\\/////\\\____/\\\///////\\\_
  ________/\\\/\\\_____/\\\____\//\\\__\///______/\\\__
   ______/\\\/\/\\\____\/\\\_____\/\\\_________/\\\//___
    ____/\\\/__\/\\\____\/\\\_____\/\\\________\////\\\__
     __/\\\\\\\\\\\\\\\\_\/\\\_____\/\\\___________\//\\\_
      _\///////////\\\//__\//\\\____/\\\___/\\\______/\\\__
       ___________\/\\\_____\///\\\\\\\/___\///\\\\\\\\\/___
        ___________\///________\///////_______\/////////_____"""
        
        logo_lines = logo_raw.strip('\n').split('\n')
        
        print()
        # Print centered logo
        for line in logo_lines:
            centered_line = line.center(terminal_width)
            print(f"{c.CYAN}{centered_line}{c.RESET}")
        
        print()
        
        # Print text info inside a centered box
        box_width = 62
        line1 = f"FIREFOX HARDENER v{self.VERSION}"
        line2 = "Enterprise Policy-Based Configuration Tool"
        
        # Calculate the left padding to center the box
        left_padding = ' ' * ((terminal_width - box_width) // 2)

        print(f"{left_padding}{c.CYAN}╔{'═' * (box_width-2)}╗{c.RESET}")
        print(f"{left_padding}{c.CYAN}║{c.RESET}{c.BOLD}{line1.center(box_width-2)}{c.RESET}{c.CYAN}║{c.RESET}")
        print(f"{left_padding}{c.CYAN}║{c.RESET}{line2.center(box_width-2)}{c.CYAN}║{c.RESET}")
        print(f"{left_padding}{c.CYAN}╚{'═' * (box_width-2)}╝{c.RESET}")
        print()
        
    def detect_firefox_installation(self) -> dict:
        """Comprehensive check for Firefox installation and version."""
        info = {'installed': False, 'path': None, 'version': None, 'install_method': None}
        if self.is_linux:
            checks = [
                ('/usr/bin/firefox', 'package_manager'),
                ('/usr/lib/firefox/firefox', 'package_manager'),
                ('/opt/firefox/firefox', 'manual'),
                ('/snap/bin/firefox', 'snap'),
                (str(Path.home() / '.local/share/applications/firefox/firefox'), 'local'),
            ]
            for firefox_path, method in checks:
                if Path(firefox_path).exists():
                    info.update({'installed': True, 'path': firefox_path, 'install_method': method})
                    break
        elif self.is_mac:
            p = '/Applications/Firefox.app/Contents/MacOS/firefox'
            if Path(p).exists():
                info.update({'installed': True, 'path': p, 'install_method': 'app'})
        elif self.is_windows:
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Mozilla\Mozilla Firefox") as key:
                    current_version, _ = winreg.QueryValueEx(key, "CurrentVersion")
                    with winreg.OpenKey(key, fr"{current_version}\Main") as main_key:
                        path_to_exe, _ = winreg.QueryValueEx(main_key, "PathToExe")
                        if Path(path_to_exe).exists():
                            info.update({'installed': True, 'path': path_to_exe, 'install_method': 'installer'})
            except FileNotFoundError:
                prog_files = Path(os.environ.get('ProgramFiles', 'C:/Program Files'))
                p = prog_files / "Mozilla Firefox/firefox.exe"
                if p.exists():
                    info.update({'installed': True, 'path': str(p), 'install_method': 'installer'})

        if info.get('path'):
            try:
                result = subprocess.run([info['path'], '--version'], capture_output=True, text=True, check=True)
                version_str = result.stdout.strip().split()[-1]
                info['version'] = version_str
            except Exception:
                pass
        return info

    def install_firefox(self) -> bool:
        """Install Firefox using the appropriate method for the OS."""
        c = Colors
        print(f"\n{c.YELLOW}[*] Checking for Firefox installation method...{c.RESET}")
        
        if self.is_linux:
            distro_info = self._detect_linux_distro()
            print(f"[*] Detected: {distro_info['name']}")
            
            if distro_info['is_tails']:
                print(f"{c.YELLOW}[!] Tails OS detected. Firefox (Tor Browser) should already be installed.{c.RESET}")
                print("[*] If you need standard Firefox, install it manually.")
                return False
            
            if shutil.which('apt-get'):
                print("[*] Using APT package manager...")
                commands = [
                    ['sudo', 'apt-get', 'update'],
                    ['sudo', 'apt-get', 'install', '-y', 'firefox-esr']
                ]
                try:
                    for cmd in commands:
                        print(f"[*] Running: {' '.join(cmd)}")
                        subprocess.run(cmd, check=True)
                    print(f"{c.GREEN}[+] Firefox ESR installed successfully.{c.RESET}")
                    return True
                except subprocess.CalledProcessError:
                    try:
                        print("[*] Trying standard Firefox package...")
                        subprocess.run(['sudo', 'apt-get', 'install', '-y', 'firefox'], check=True)
                        print(f"{c.GREEN}[+] Firefox installed successfully.{c.RESET}")
                        return True
                    except Exception as e:
                        print(f"{c.RED}[!] Installation failed: {e}{c.RESET}")
                        return False
                        
            elif shutil.which('dnf'):
                print("[*] Using DNF package manager...")
                try:
                    subprocess.run(['sudo', 'dnf', 'install', '-y', 'firefox'], check=True)
                    print(f"{c.GREEN}[+] Firefox installed successfully.{c.RESET}")
                    return True
                except Exception as e:
                    print(f"{c.RED}[!] Installation failed: {e}{c.RESET}")
                    return False
                    
            elif shutil.which('pacman'):
                print("[*] Using Pacman package manager...")
                try:
                    subprocess.run(['sudo', 'pacman', '-Sy', '--noconfirm', 'firefox'], check=True)
                    print(f"{c.GREEN}[+] Firefox installed successfully.{c.RESET}")
                    return True
                except Exception as e:
                    print(f"{c.RED}[!] Installation failed: {e}{c.RESET}")
                    return False
                    
            elif shutil.which('snap'):
                print("[*] Using Snap package manager...")
                print(f"{c.YELLOW}[!] Note: Snap Firefox has limitations with system policies.{c.RESET}")
                if input("Install via snap anyway? [y/N]: ").lower() == 'y':
                    try:
                        subprocess.run(['sudo', 'snap', 'install', 'firefox'], check=True)
                        print(f"{c.GREEN}[+] Firefox installed via snap.{c.RESET}")
                        print(f"{c.YELLOW}[!] Warning: Policy application may be limited with snap installation.{c.RESET}")
                        return True
                    except Exception as e:
                        print(f"{c.RED}[!] Installation failed: {e}{c.RESET}")
                        return False
            else:
                print(f"{c.RED}[!] No supported package manager found.{c.RESET}")
                print("[*] Please install Firefox manually using your distribution's method.")
                return False
                
        elif self.is_mac:
            if shutil.which('brew'):
                print("[*] Using Homebrew...")
                try:
                    subprocess.run(['brew', 'install', '--cask', 'firefox'], check=True)
                    print(f"{c.GREEN}[+] Firefox installed successfully.{c.RESET}")
                    return True
                except Exception as e:
                    print(f"{c.RED}[!] Installation failed: {e}{c.RESET}")
                    return False
            else:
                print(f"{c.RED}[!] Homebrew not found. Please install Firefox manually from mozilla.org.{c.RESET}")
                return False
                
        elif self.is_windows:
            print("[*] Windows detected. Please download Firefox from mozilla.org")
            print("[*] Download URL: https://www.mozilla.org/firefox/")
            input("Press Enter after installation is complete...")
            return True
    
    def _detect_linux_distro(self) -> dict:
        info = {'name': 'Unknown Linux', 'is_tails': False, 'is_debian_based': False}
        if Path('/etc/dpkg/origins/TailsOS').exists():
            info['name'] = 'Tails OS'
            info['is_tails'] = True
            info['is_debian_based'] = True
            return info
        try:
            with open('/etc/os-release', 'r') as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith('NAME='):
                        info['name'] = line.split('=')[1].strip().strip('"')
                    if line.startswith('ID_LIKE=') or line.startswith('ID='):
                        id_value = line.split('=')[1].strip().strip('"').lower()
                        if 'debian' in id_value or 'ubuntu' in id_value:
                            info['is_debian_based'] = True
        except:
            pass
        if 'Pop!_OS' in info['name'] or 'pop' in info['name'].lower():
            info['name'] = 'Pop!_OS'
            info['is_debian_based'] = True
        return info

    def find_firefox_profiles(self) -> List[Path]:
        profiles = []
        search_paths = [
            Path.home() / p for p in [
                ".mozilla/firefox",
                "Library/Application Support/Firefox/Profiles",
                "AppData/Roaming/Mozilla/Firefox/Profiles",
                "snap/firefox/common/.mozilla/firefox"
            ]
        ]
        for search_path in search_paths:
            if search_path.exists():
                for item in search_path.iterdir():
                    if item.is_dir() and (item / "prefs.js").exists():
                        profiles.append(item)
        return profiles

    def select_profile(self) -> Optional[Path]:
        c = Colors
        profiles = self.find_firefox_profiles()
        if not profiles:
            print(f"\n{c.RED}[ERROR] No Firefox profiles found! Please run Firefox at least once.{c.RESET}")
            return None
        if len(profiles) == 1:
            print(f"\n[*] Using automatically detected profile: {c.GREEN}{profiles[0].name}{c.RESET}")
            return profiles[0]
        
        print(f"\n[*] Multiple Firefox profiles found:")
        for i, profile in enumerate(profiles, 1):
            print(f"    {c.CYAN}{i}.{c.RESET} {profile.name} ({profile.parent})")
        while True:
            try:
                idx = int(input(f"\n{c.BOLD}> Select profile [1-{len(profiles)}]: {c.RESET}")) - 1
                if 0 <= idx < len(profiles):
                    return profiles[idx]
            except (ValueError, IndexError):
                pass
            print(f"{c.YELLOW}[!] Invalid selection.{c.RESET}")

    def _pre_operation_backup_prompt(self, profile: Path):
        """Asks the user if they want to back up before a risky operation."""
        c = Colors
        prompt = f"\n{c.YELLOW}[!] It is highly recommended to back up this profile before proceeding.\n    Create a backup of '{profile.name}' now? [Y/n]: {c.RESET}"
        response = input(prompt).strip().lower()
        if response != 'n':
            self.create_backup(profile)

    def create_backup(self, profile_path: Path):
        c = Colors
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"profile_backup_{profile_path.name}_{timestamp}"
        dest_path = self.backup_dir / backup_name
        
        print(f"\n[*] Creating backup of profile: {c.GREEN}{profile_path.name}{c.RESET}")
        print(f"    Destination: {dest_path}.zip")
        
        try:
            print("    [*] Compressing profile data...")
            shutil.make_archive(str(dest_path), 'zip', str(profile_path))
            backup_size = (dest_path.with_suffix('.zip')).stat().st_size / (1024 * 1024)
            
            print(f"\n{c.GREEN}╔{'═' * 58}╗{c.RESET}")
            print(f"{c.GREEN}║{'BACKUP CREATED SUCCESSFULLY'.center(58)}║{c.RESET}")
            print(f"{c.GREEN}╟{'─' * 58}╢{c.RESET}")
            print(f"{c.GREEN}║{c.RESET}{f'Profile: {profile_path.name}'.center(58)}{c.GREEN}║{c.RESET}")
            print(f"{c.GREEN}║{c.RESET}{f'Size: {backup_size:.1f} MB'.center(58)}{c.GREEN}║{c.RESET}")
            print(f"{c.GREEN}║{c.RESET}{f'Location: backups/{backup_name}.zip'.center(58)}{c.GREEN}║{c.RESET}")
            print(f"{c.GREEN}╚{'═' * 58}╝{c.RESET}")
        except Exception as e:
            print(f"\n{c.RED}[-] Backup failed: {e}{c.RESET}")

    def restore_backup(self, profile_to_restore: Path):
        """Restores a profile from a backup, with an explicit disclaimer."""
        c = Colors
        backups = sorted(self.backup_dir.glob("*.zip"), reverse=True)
        if not backups:
            print(f"\n{c.YELLOW}[!] No profile backups found in the 'backups' directory.{c.RESET}")
            return

        print("\n[*] Available backups:")
        for i, backup in enumerate(backups, 1):
            print(f"    {c.CYAN}{i}.{c.RESET} {backup.name}")
        try:
            idx = int(input(f"\n{c.BOLD}> Select backup to restore [1-{len(backups)}]: {c.RESET}")) - 1
            if 0 <= idx < len(backups):
                backup_file = backups[idx]
                
                print(f"\n{c.RED}╔{'═' * 60}╗{c.RESET}")
                print(f"{c.RED}║{c.BOLD}{'WARNING: DESTRUCTIVE ACTION'.center(60)}{c.RESET}{c.RED}║{c.RESET}")
                print(f"{c.RED}╟{'─' * 60}╢{c.RESET}")
                print(f"{c.RED}║{c.RESET} This will {c.BOLD}PERMANENTLY DELETE{c.RESET} your current Firefox profile:".ljust(69) + f"{c.RED}║{c.RESET}")
                print(f"{c.RED}║{c.YELLOW}{str(profile_to_restore).center(60)}{c.RESET}{c.RED}║{c.RESET}")
                print(f"{c.RED}║{c.RESET} It will be replaced with the backup file:".ljust(69) + f"{c.RED}║{c.RESET}")
                print(f"{c.RED}║{c.YELLOW}{backup_file.name.center(60)}{c.RESET}{c.RED}║{c.RESET}")
                print(f"{c.RED}║{c.RESET} Any data saved since the backup was made will be {c.BOLD}LOST FOREVER.{c.RESET}".ljust(79) + f"{c.RED}║{c.RESET}")
                print(f"{c.RED}║{c.RESET} This action CANNOT be undone.".ljust(69) + f"{c.RED}║{c.RESET}")
                print(f"{c.RED}╚{'═' * 60}╝{c.RESET}")
                
                confirm = input(f"\n{c.BOLD}> Type '{c.YELLOW}yes{c.RESET}{c.BOLD}' to confirm and proceed: {c.RESET}").strip().lower()
                
                if confirm == 'yes':
                    print(f"\n[*] Restoring '{backup_file.name}'...")
                    if profile_to_restore.exists():
                        shutil.rmtree(profile_to_restore)
                    shutil.unpack_archive(str(backup_file), str(profile_to_restore), 'zip')
                    print(f"{c.GREEN}[+] Restore complete.{c.RESET}")
                else:
                    print(f"{c.YELLOW}[*] Restore cancelled.{c.RESET}")
            else:
                print(f"{c.YELLOW}[!] Invalid selection.{c.RESET}")
        except Exception as e:
            print(f"{c.RED}[!] Restore failed: {e}{c.RESET}")

    def _get_firefox_install_path(self) -> Optional[Path]:
        info = self.detect_firefox_installation()
        if not info['path']: return None
        exe_path = Path(os.path.realpath(info['path']))
        if self.is_mac: return exe_path.parents[2]
        if self.is_windows: return exe_path.parent
        if info['install_method'] == 'snap': return Path('/etc/firefox')
        if exe_path.parent.name == "bin":
            lib_path = exe_path.parent.parent / "lib" / "firefox"
            if lib_path.exists(): return lib_path
        return exe_path.parent

    def _get_policy_paths(self) -> List[Path]:
        paths = []
        if self.is_linux:
            paths.extend([
                Path("/etc/firefox/policies"),
                Path("/usr/lib/firefox/distribution"),
                Path("/usr/lib64/firefox/distribution"),
                Path("/etc/firefox/distribution"),
                Path("/usr/share/firefox/distribution"),
            ])
            install_path = self._get_firefox_install_path()
            if install_path: paths.append(install_path / "distribution")
        elif self.is_mac:
            install_path = self._get_firefox_install_path()
            if install_path: paths.append(install_path / "Contents/Resources/distribution")
        elif self.is_windows:
            paths.append(Path(os.environ.get('ProgramData', 'C:/ProgramData')) / "Mozilla/Firefox")
            install_path = self._get_firefox_install_path()
            if install_path: paths.append(install_path / "distribution")
        
        seen = set()
        return [p for p in paths if not (p in seen or seen.add(p))]

    def _generate_policies(self, options: dict) -> dict:
        policy = {"policies": {
            "DisableTelemetry": True, "DisableFirefoxStudies": True, "DisablePocket": True,
            "DontCheckDefaultBrowser": True, "OfferToSaveLogins": False, "PasswordManagerEnabled": False,
            "DisableFormHistory": True, "DisableFirefoxAccounts": False, "DisableSetDesktopBackground": True,
            "NoDefaultBookmarks": True, "OverrideFirstRunPage": "", "OverridePostUpdatePage": "",
            "SearchEngines": {"Default": "DuckDuckGo", "PreventInstalls": True},
            "Extensions": {"Install": []},
            "ExtensionSettings": {},
            "Preferences": {
                "privacy.globalprivacycontrol.enabled": {"Value": True, "Status": "default"},
                "privacy.donottrackheader.enabled": {"Value": True, "Status": "default"},
                "privacy.trackingprotection.enabled": {"Value": True, "Status": "default"},
                "privacy.trackingprotection.socialtracking.enabled": {"Value": True, "Status": "default"},
                "privacy.trackingprotection.cryptomining.enabled": {"Value": True, "Status": "default"},
                "privacy.trackingprotection.fingerprinting.enabled": {"Value": True, "Status": "default"},
                "extensions.formautofill.addresses.enabled": {"Value": False, "Status": "default"},
                "extensions.formautofill.creditCards.enabled": {"Value": False, "Status": "default"},
                "signon.rememberSignons": {"Value": False, "Status": "default"},
                "network.dns.disablePrefetch": {"Value": True, "Status": "default"},
                "network.predictor.enabled": {"Value": False, "Status": "default"},
                "network.prefetch-next": {"Value": False, "Status": "default"},
                "media.peerconnection.ice.default_address_only": {"Value": True, "Status": "default"},
                "media.peerconnection.ice.no_host": {"Value": True, "Status": "default"},
                "privacy.resistFingerprinting": {"Value": True, "Status": "default"},
                "privacy.resistFingerprinting.letterboxing": {"Value": True, "Status": "default"},
                "dom.security.https_only_mode": {"Value": True, "Status": "default"},
                "dom.security.https_only_mode_ever_enabled": {"Value": True, "Status": "default"},
            }}}
        
        if options.get('install_extensions') and options.get('selected_extensions'):
            for ext_key in options['selected_extensions']:
                ext_info = self.extensions[ext_key]
                policy["policies"]["Extensions"]["Install"].append(ext_info['url'])
                policy["policies"]["ExtensionSettings"][ext_info['id']] = {
                    "installation_mode": "force_installed", "install_url": ext_info['url'],
                    "allowed_types": ["extension"], "updates_disabled": False
                }
            policy["policies"]["ExtensionSettings"]["*"] = {
                "installation_mode": "blocked",
                "blocked_install_message": "Installation of additional extensions is blocked by security policy."
            }
        return policy

    def apply_policies(self, options: dict):
        c = Colors
        policy_paths = self._get_policy_paths()
        if not policy_paths:
            print(f"\n{c.RED}[!] Could not determine Firefox policy directory. Aborting.{c.RESET}")
            return
        
        print(f"\n{c.CYAN}┌─ Applying Security Policies{c.RESET}")
        print(f"{c.CYAN}│{c.RESET}  Checking {len(policy_paths)} possible locations...")
        print(f"{c.CYAN}└{'─' * 40}{c.RESET}")
        
        success, errors, successful_path = False, [], None
        for policy_path in policy_paths:
            policy_file = policy_path / "policies.json"
            print(f"    → Trying: {policy_file}")
            try:
                policy_path.mkdir(parents=True, exist_ok=True)
                policy_content = self._generate_policies(options)
                with open(policy_file, 'w', encoding='utf-8') as f:
                    json.dump(policy_content, f, indent=4)
                if policy_file.exists() and policy_file.stat().st_size > 0:
                    print(f"    {c.GREEN}[+] SUCCESS: Policy written to {policy_file}{c.RESET}")
                    successful_path, success = policy_file, True
                    break
                else: errors.append(f"File verification failed: {policy_file}")
            except PermissionError: errors.append(f"Permission denied: {policy_file}")
            except OSError as e: errors.append(f"Read-only filesystem: {policy_file}" if "Read-only file system" in str(e) else f"OS error for {policy_file}: {e}")
            except Exception as e: errors.append(f"Unexpected error for {policy_file}: {e}")
        
        if not success:
            print(f"\n{c.RED}╔{'═' * 58}╗{c.RESET}")
            print(f"{c.RED}║{'POLICY APPLICATION FAILED'.center(58)}║{c.RESET}")
            print(f"{c.RED}╚{'═' * 58}╝{c.RESET}")
            print("\n[!] Failed to write to any policy location:")
            for error in errors: print(f"    • {error}")
            print("\n[*] This might be a permission issue. Ensure you're running with sudo.")
            print("    You can also try creating /etc/firefox/policies/ manually.")
        else:
            print(f"\n{c.GREEN}╔{'═' * 58}╗{c.RESET}")
            print(f"{c.GREEN}║{'POLICIES APPLIED SUCCESSFULLY!'.center(58)}║{c.RESET}")
            print(f"{c.GREEN}╚{'═' * 58}╝{c.RESET}")
            print(f"\n[*] Policy location: {successful_path}")
            print(f"\n{c.CYAN}┌─ Configuration Summary{c.RESET}")
            print(f"{c.CYAN}│{c.RESET}")
            print(f"{c.CYAN}│{c.RESET}   {c.GREEN}[+]{c.RESET} Core Privacy Settings Applied:")
            print(f"{c.CYAN}│{c.RESET}       • Telemetry and data collection disabled")
            print(f"{c.CYAN}│{c.RESET}       • Firefox Studies disabled")
            print(f"{c.CYAN}│{c.RESET}       • Pocket integration removed")
            print(f"{c.CYAN}│{c.RESET}       • Enhanced tracking protection enabled")
            print(f"{c.CYAN}│{c.RESET}       • HTTPS-Only mode activated")
            print(f"{c.CYAN}│{c.RESET}       • Fingerprinting resistance enabled")
            print(f"{c.CYAN}│{c.RESET}       • DuckDuckGo set as default search engine")
            if options.get('selected_extensions'):
                print(f"{c.CYAN}│{c.RESET}")
                print(f"{c.CYAN}│{c.RESET}   {c.GREEN}[+]{c.RESET} Extensions Configured ({len(options['selected_extensions'])} total):")
                descriptions = {'ublock_origin': 'Ad & tracker blocking', 'multi_account_containers': 'Isolate sites in containers', 'temporary_containers': 'Auto-disposable containers', 'localcdn': 'CDN request protection', 'clearurls': 'Remove tracking from URLs', 'canvasblocker': 'Prevent canvas fingerprinting'}
                for ext_key in options['selected_extensions']:
                    ext = self.extensions[ext_key]
                    desc = descriptions.get(ext_key, 'Privacy protection')
                    print(f"{c.CYAN}│{c.RESET}       • {ext['name']}")
                    print(f"{c.CYAN}│{c.RESET}         └─ {desc}")
            print(f"{c.CYAN}└{'─' * 40}{c.RESET}")
            print(f"\n{c.YELLOW}NEXT STEPS:{c.RESET}")
            print(f"{c.CYAN}┌{'─' * 58}┐{c.RESET}")
            print(f"{c.CYAN}│{c.RESET}  1. Close all Firefox windows completely                     {c.CYAN}│{c.RESET}")
            print(f"{c.CYAN}│{c.RESET}  2. Start Firefox as normal user (not root)                  {c.CYAN}│{c.RESET}")
            print(f"{c.CYAN}│{c.RESET}  3. Extensions will auto-download (requires internet)        {c.CYAN}│{c.RESET}")
            print(f"{c.CYAN}│{c.RESET}  4. Verify: Type 'about:policies' in address bar             {c.CYAN}│{c.RESET}")
            print(f"{c.CYAN}│{c.RESET}  5. Check: Type 'about:addons' to see extensions             {c.CYAN}│{c.RESET}")
            print(f"{c.CYAN}└{'─' * 58}┘{c.RESET}")
            if options.get('selected_extensions'):
                print("\n[*] Note: First startup may take 30-60 seconds while")
                print("    Firefox downloads and installs the extensions.")

    def remove_policies(self):
        c = Colors
        policy_paths = self._get_policy_paths()
        removed = False
        print(f"\n{c.YELLOW}Removing Firefox hardening policies...{c.RESET}")
        for policy_path in policy_paths:
            policy_file = policy_path / "policies.json"
            if policy_file.exists():
                try:
                    policy_file.unlink()
                    print(f"    {c.GREEN}[+] Removed: {policy_file}{c.RESET}")
                    removed = True
                except PermissionError:
                    print(f"    {c.RED}[-] Permission denied: {policy_file}{c.RESET}")
                    print("        Try running with sudo/administrator privileges.")
                except Exception as e:
                    print(f"    {c.YELLOW}[!] Error removing {policy_file}: {e}{c.RESET}")
        
        if removed:
            print(f"\n{c.GREEN}╔{'═' * 58}╗{c.RESET}")
            print(f"{c.GREEN}║{'POLICIES REMOVED SUCCESSFULLY'.center(58)}║{c.RESET}")
            print(f"{c.GREEN}╟{'─' * 58}╢{c.RESET}")
            print(f"{c.GREEN}║{c.RESET}{'Firefox will return to default settings on restart'.center(58)}{c.GREEN}║{c.RESET}")
            print(f"{c.GREEN}║{c.RESET}{'Extensions may remain but wont be force-installed'.center(58)}{c.GREEN}║{c.RESET}")
            print(f"{c.GREEN}╚{'═' * 58}╝{c.RESET}")
            print("\nNext steps:")
            print("    1. Restart Firefox to apply changes")
            print("    2. Manually remove extensions if desired (about:addons)")
        else:
            print(f"\n{c.YELLOW}╔{'═' * 58}╗{c.RESET}")
            print(f"{c.YELLOW}║{'NO POLICIES FOUND'.center(58)}║{c.RESET}")
            print(f"{c.YELLOW}╟{'─' * 58}╢{c.RESET}")
            print(f"{c.YELLOW}║{'No active policy files were found to remove'.center(58)}║{c.RESET}")
            print(f"{c.YELLOW}╚{'═' * 58}╝{c.RESET}")

    def verify_hardening(self):
        c = Colors
        policy_paths = self._get_policy_paths()
        print(f"\n{c.CYAN}╔{'═' * 58}╗{c.RESET}")
        print(f"{c.CYAN}║{c.RESET}{'HARDENING STATUS REPORT'.center(58)}{c.CYAN}║{c.RESET}")
        print(f"{c.CYAN}╚{'═' * 58}╝{c.RESET}")
        active_policies = [p / "policies.json" for p in policy_paths if (p / "policies.json").exists()]
        if not active_policies:
            print(f"\n{c.RED}╔{'═' * 58}╗{c.RESET}")
            print(f"{c.RED}║{'NO HARDENING DETECTED'.center(58)}║{c.RESET}")
            print(f"{c.RED}╟{'─' * 58}╢{c.RESET}")
            print(f"{c.RED}║{'No active policies found. Your Firefox is using'.center(58)}║{c.RESET}")
            print(f"{c.RED}║{'default settings. Run an installation option to'.center(58)}║{c.RESET}")
            print(f"{c.RED}║{'apply security hardening.'.center(58)}║{c.RESET}")
            print(f"{c.RED}╚{'═' * 58}╝{c.RESET}")
            return
        for policy_file in active_policies:
            try:
                with open(policy_file, 'r') as f:
                    policy_data = json.load(f)
                print(f"\n{c.CYAN}┌─ Policy Configuration{c.RESET}")
                print(f"{c.CYAN}│{c.RESET}  Location: {policy_file}")
                print(f"{c.CYAN}│{c.RESET}  Status: {c.GREEN}ACTIVE{c.RESET}")
                print(f"{c.CYAN}└{'─' * 40}{c.RESET}")
            except Exception as e:
                print(f"\n{c.RED}[!] Error reading policy file {policy_file}: {e}{c.RESET}")

    def custom_install_menu(self) -> dict:
        c = Colors
        print(f"\n{c.CYAN}╔{'═' * 58}╗{c.RESET}")
        print(f"{c.CYAN}║{c.RESET}{c.BOLD}{'CUSTOM INSTALLATION'.center(58)}{c.RESET}{c.CYAN}║{c.RESET}")
        print(f"{c.CYAN}╚{'═' * 58}╝{c.RESET}")
        print("\n[*] Core privacy policies will be applied automatically.")
        print("Select which extensions to install:\n")
        options = {'install_extensions': True, 'selected_extensions': []}
        for key, info in self.extensions.items():
            response = input(f"    Install {c.GREEN}{info['name']}{c.RESET}? [Y/n]: ").strip().lower()
            if response != 'n':
                options['selected_extensions'].append(key)
                print(f"        {c.GREEN}[+] {info['name']} will be installed{c.RESET}")
            else:
                print(f"        {c.YELLOW}[-] Skipping {info['name']}{c.RESET}")
        if options['selected_extensions']:
            print(f"\nReady to install {len(options['selected_extensions'])} extension(s)")
        else:
            print("\nNo extensions selected - only core policies will be applied")
        return options
        
    def show_menu(self) -> str:
        """Display main menu with corrected alignment, colors, and grouping."""
        c = Colors
        inner_width = 58
        
        menu_groups = [
            [
                ("1", "Quick Install - Balanced Security", "→ uBlock, Containers, ClearURLs, LocalCDN"),
                ("2", "Quick Install - Maximum Security", "→ All 6 privacy extensions + maximum hardening"),
                ("3", "Custom Installation", "→ Choose your own extension combination"),
            ],
            [
                ("4", "Remove All Policies", "→ Restore Firefox to default settings"),
                ("5", "Backup Firefox Profile", None),
                ("6", "Restore Profile Backup", None),
                ("7", "Verify Hardening Status", None),
                ("8", "Install/Update Firefox", None),
            ],
            [
                ("9", "Exit", None),
            ]
        ]

        print(f"\n{c.CYAN}┌{'─' * (inner_width + 2)}┐{c.RESET}")
        print(f"{c.CYAN}│{c.RESET}{'MAIN MENU'.center(inner_width + 2)}{c.CYAN}│{c.RESET}")
        
        for group in menu_groups:
            print(f"{c.CYAN}├{'─' * (inner_width + 2)}┤{c.RESET}")
            for num, title, sub in group:
                main_line_text = f"  {c.CYAN}{num}.{c.RESET} {c.GREEN}{title}{c.RESET}"
                padding = ' ' * (inner_width - visible_len(main_line_text))
                print(f"{c.CYAN}│{c.RESET}{main_line_text}{padding}  {c.CYAN}│{c.RESET}")

                if sub:
                    sub_line_text = f"      {sub}"
                    padding = ' ' * (inner_width - visible_len(sub_line_text))
                    print(f"{c.CYAN}│{c.RESET}{sub_line_text}{padding}  {c.CYAN}│{c.RESET}")

        print(f"{c.CYAN}└{'─' * (inner_width + 2)}┘{c.RESET}")
        
        while True:
            choice = input(f"\n{c.BOLD}> Select option [1-9]: {c.RESET}").strip()
            if choice in [str(i) for i in range(1, 10)]:
                return choice
            print(f"{c.YELLOW}[!] Invalid option. Please select 1-9.{c.RESET}")

    def run(self):
        c = Colors
        self.display_header()
        print("Detecting Firefox installation...")
        ff_info = self.detect_firefox_installation()
        if ff_info['installed']:
            print(f"{c.GREEN}[+] Firefox v{ff_info.get('version', 'Unknown')} detected{c.RESET}")
            print(f"    Location: {ff_info.get('path')}")
            print(f"    Install method: {ff_info.get('install_method')}")
        else:
            print(f"{c.RED}[-] Firefox is not installed.{c.RESET}")
            if input(f"\n{c.BOLD}> Install Firefox now? [Y/n]: {c.RESET}").strip().lower() != 'n':
                if not self.install_firefox():
                    print(f"\n{c.RED}[!] Please install Firefox manually and re-run this script.{c.RESET}")
                    sys.exit(1)
            else:
                print(f"\n{c.YELLOW}[!] Firefox is required to continue.{c.RESET}")
                sys.exit(1)

        while True:
            choice = self.show_menu()
            
            profile = None
            profile_choices = ['1', '2', '3', '5', '6']
            backup_prompt_choices = ['1', '2', '3', '6']

            if choice in profile_choices:
                print("\n[*] An operation has been selected that requires a Firefox profile.")
                profile = self.select_profile()
                if not profile:
                    print(f"{c.YELLOW}[!] No profile selected. Returning to main menu.{c.RESET}")
                    input(f"\n{c.BOLD}> Press Enter to continue...{c.RESET}")
                    continue
                
                if choice in backup_prompt_choices:
                    self._pre_operation_backup_prompt(profile)

            if choice == '9':
                print("\nExiting Firefox Hardener. Stay safe!\n")
                break
            elif choice in ['1', '2', '3']:
                options = {}
                if choice == '1':
                    print(f"\n{c.GREEN}Applying balanced security configuration...{c.RESET}")
                    options = {'install_extensions': True, 'selected_extensions': ['ublock_origin', 'multi_account_containers', 'clearurls', 'localcdn']}
                elif choice == '2':
                    print(f"\n{c.GREEN}Applying maximum security configuration...{c.RESET}")
                    options = {'install_extensions': True, 'selected_extensions': list(self.extensions.keys())}
                elif choice == '3':
                    options = self.custom_install_menu()
                
                if options.get('selected_extensions') or input(f"\n{c.BOLD}> Apply policies without extensions? [y/N]: {c.RESET}").lower() == 'y':
                    self.apply_policies(options)

            elif choice == '4': self.remove_policies()
            elif choice == '5':
                if profile:
                    self.create_backup(profile)
            elif choice == '6':
                if profile:
                    self.restore_backup(profile)
            elif choice == '7': self.verify_hardening()
            elif choice == '8': self.install_firefox()
            
            if choice != '9':
                input(f"\n{c.BOLD}> Press Enter to continue...{c.RESET}")

def main():
    """Main entry point with error handling."""
    if sys.platform == "win32":
        os.system("color")
        
    c = Colors
    if sys.platform.startswith('linux'):
        if os.geteuid() != 0:
            print(f"{c.YELLOW}{'=' * 60}{c.RESET}")
            print(f"{c.YELLOW}{'PERMISSION REQUIRED'.center(60)}{c.RESET}")
            print(f"{c.YELLOW}{'=' * 60}{c.RESET}")
            print("\nThis script requires root privileges to apply system-wide policies.")
            print(f"Please run with: {c.CYAN}sudo python3 your_script_name.py{c.RESET}\n")
            sys.exit(1)
    
    try:
        hardener = FirefoxHardener()
        hardener.run()
    except KeyboardInterrupt:
        print(f"\n\n{c.YELLOW}[!] Operation cancelled by user.{c.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{c.RED}[!] Fatal error: {e}{c.RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()