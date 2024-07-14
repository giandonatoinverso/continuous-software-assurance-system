import re
import json


class LinpeasParser:
    def __init__(self, report_file_path):
        self.report = report_file_path
        self.environment = dict
        self.socket_files = dict
        self.dbus_config_files = dict
        self.superusers = dict
        self.users_with_console = dict
        self.users_and_group = dict
        self.certificates = dict
        self.writable_ssh_pgp = dict
        self.writable_files = dict
        self.sh_files = dict
        self.unexpected_files = dict
        self.sgid = dict
        self.script_in_profiles = dict
        self.suid = dict
        self.service = dict
        self.capabilities = dict
        self.permissions = dict
        self.protections = dict
        self.sudo_version = dict
        self.linux_exploit_suggester = dict
        self.linux_exploit_suggester_2 = dict
        self.active_ports = dict
        self.sudo_tokens = dict

    def print_json(self, json_file):
        print(json.dumps(json_file, indent=4))
        print("\n")

    def read_environment(self):
        self.environment = self._read_standard("Environment", "environment")
        return self

    def get_environment(self):
        return self.environment

    def read_socket_files(self):
        self.socket_files = self._read_standard("Analyzing .socket files", "socket_files")
        return self

    def get_socket_files(self):
        return self.socket_files

    def read_superusers(self):
        self.superusers = self._read_standard("Superusers", "superusers")
        return self

    def get_superusers(self):
        return self.superusers

    def read_dbus_config_files(self):
        self.dbus_config_files = self._read_standard("D-Bus config files", "dbus_config_files")
        return self

    def get_dbus_config_files(self):
        return self.dbus_config_files

    def read_users_with_console(self):
        self.users_with_console = self._read_standard("Users with console", "users_with_console")
        return self

    def get_users_with_console(self):
        return self.users_with_console

    def read_users_and_group(self):
        self.users_and_group = self._read_standard("All users & groups", "users_and_group")
        return self

    def get_users_and_group(self):
        return self.users_and_group

    def read_certificates(self):
        self.certificates = self._read_standard("Some certificates were found (out limited):", "certificates")
        return self

    def get_certificates(self):
        return self.certificates

    def read_writable_ssh_pgp(self):
        self.writable_ssh_pgp = self._read_standard("Writable ssh and gpg agents", "writable_ssh_pgp")
        return self

    def get_writable_ssh_pgp(self):
        return self.writable_ssh_pgp

    def read_writable_files(self):
        self.writable_files = self._read_standard("Interesting writable files owned by me or writable by everyone (not in Home) (max 500)", "writable_files")
        return self

    def get_writable_files(self):
        return self.writable_files

    def read_sh_files(self):
        self.sh_files = self._read_standard(".sh files in path", "sh_files")
        return self

    def get_sh_files(self):
        return self.sh_files

    def read_unexpected_files(self):
        self.unexpected_files = self._read_standard("Unexpected in root", "unexpected_files")
        return self

    def get_unexpected_files(self):
        return self.unexpected_files

    def read_sudo_tokens(self):
        self.sudo_tokens = self._read_standard("Checking sudo tokens", "sudo_tokens")
        return self

    def get_sudo_tokens(self):
        return self.sudo_tokens

    def read_sgid(self):
        self.sgid = self._read_last_column("SGID", "sgid")
        return self

    def get_sgid(self):
        return self.sgid

    def read_script_in_profiles(self):
        self.script_in_profiles = self._read_last_column("Files (scripts) in /etc/profile.d/", "script_in_profiles")
        return self

    def get_script_in_profiles(self):
        return self.script_in_profiles

    def read_suid(self):
        self.suid = self._read_last_column("SUID - Check easy privesc, exploits and write perms", "suid")
        return self

    def get_suid(self):
        return self.suid

    def read_service(self):
        parsed_data = {"service": [], "systemd": None}

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '╔══════════╣ Analyzing .service files' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╔══════════╣') or line.startswith('══╣'):
                        break
                    if line.startswith('╚'):
                        continue
                    elif line.strip():
                        if "You can't write on systemd PATH" in line:
                            parsed_data["systemd"] = False
                        elif "You can write on systemd PATH" in line:
                            parsed_data["systemd"] = True
                        else:
                            parsed_data["service"].append(line.strip())

            self.service = {"metadata": {"test_name": "service"}, "data": parsed_data}
            return self

    def get_service(self):
        return self.service

    def read_capabilities(self):
        capabilities_data = {"Current shell capabilities": {}, "Parent process capabilities": {},
                             "Files with capabilities": {}}

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            current_section = None
            for line in file_content:
                if '╔══════════╣ Capabilities' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╔══════════╣'):
                        break
                    elif line.startswith('╚'):
                        continue
                    elif '══╣ Current shell capabilities' in line:
                        current_section = "Current shell capabilities"
                    elif '══╣ Parent process capabilities' in line:
                        current_section = "Parent process capabilities"
                    elif 'Files with capabilities' in line:
                        current_section = "Files with capabilities"

                    if current_section:
                        if 'Cap' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            if value != '0x0000000000000000=':
                                capabilities_data[current_section][key] = value
                        elif '=' in line:
                            filepath, caps = line.split(' ', 1)
                            filepath = filepath.strip()
                            caps = caps.strip()
                            capabilities_data[current_section][filepath] = caps

        self.capabilities = {"metadata": {"test_name": "capabilities"}, "data": capabilities_data}
        return self

    def get_capabilities(self):
        return self.capabilities

    def read_permissions(self):
        permissions_data = {}

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '╔══════════╣ Permissions in init, init.d, systemd, and rc.d' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╔══════════╣'):
                        break
                    elif '═╣' in line:
                        key_value = line.split('═╣', 1)[1].strip()
                        key = key_value.split('?', 1)[0].strip()
                        value = re.sub(r'\.+', '', key_value.split('?', 1)[1].strip())
                        if 'Hashes inside passwd' in key:
                            permissions_data['Hashes inside passwd'] = value
                        elif 'Writable passwd file' in key:
                            permissions_data['Writable passwd file'] = value
                        elif 'Credentials in fstab/mtab' in key:
                            permissions_data['Credentials in fstab/mtab'] = value
                        elif 'Can I read shadow files' in key:
                            permissions_data['Shadow files readable'] = value
                        elif 'Can I read shadow plists' in key:
                            permissions_data['Shadow plists readable'] = value
                        elif 'Can I write shadow plists' in key:
                            permissions_data['Shadow plists writable'] = value
                        elif 'Can I read opasswd file' in key:
                            permissions_data['Opasswd file readable'] = value
                        elif 'Can I write in network-scripts' in key:
                            permissions_data['Network-scripts writable'] = value
                        elif 'Can I read root folder' in key:
                            permissions_data['Root folder readable'] = value

        self.permissions = {"metadata": {"test_name": "permissions"}, "data": permissions_data}
        return self

    def get_permissions(self):
        return self.permissions

    def read_protections(self):
        protections_data = {}

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '╔══════════╣ Protections' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╔══════════╣'):
                        break
                    elif '═╣' in line:
                        parts = line.split('═╣', 1)
                        if len(parts) > 1:
                            key_value = parts[1].strip()
                            if '?' in key_value:
                                key, value = key_value.split('?', 1)
                                key = key.strip()
                                value = value.strip().lstrip('.').strip()
                                protections_data[key] = value
        self.protections = {"metadata": {"test_name": "protections"}, "data": protections_data}
        return self

    def get_protections(self):
        return self.protections

    def read_sudo_version(self):
        sudo_version = []

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '╔══════════╣ Sudo version' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╚'):
                        continue
                    elif 'Sudo version' in line:
                        sudo_version.append(line.split('Sudo version', 1)[1].strip())
                        break

        self.sudo_version = {"metadata": {"test_name": "sudo_version"}, "data": sudo_version}
        return self

    def get_sudo_version(self):
        return self.sudo_version

    def _parse_linux_exploit_suggester(self, key, test_name):
        cves = {}

        with open(self.report, 'r') as file:
            in_section = False
            current_cve = None
            current_info = {}

            for line in file:
                if '╔══════════╣ ' + key in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╚'):
                        continue
                    cve_match = re.search(r'\[CVE-(\d{4}-\d{4,7})\]', line)
                    if cve_match:
                        current_cve = cve_match.group().strip('[]')
                        current_info['title'] = re.search(r'\[CVE-\d{4}-\d{4,7}\]\s(.+)', line).group(1)
                        continue

                    if current_cve:
                        if "Details" in line:
                            key, value = line.split(':', 1)
                            current_info['Details'] = value.strip()
                            continue
                        if "Exposure" in line:
                            key, value = line.split(':', 1)
                            current_info['Exposure'] = value.strip()
                            continue
                        if "Tags" in line:
                            key, value = line.split(':', 1)
                            current_info['Tags'] = value.strip()
                            continue
                        if "ext-url" in line:
                            key, value = line.split(':', 1)
                            current_info['ext-url'] = value.strip()
                            continue
                        if "Comments" in line:
                            key, value = line.split(':', 1)
                            current_info['Comments'] = value.strip()
                            continue

            if current_cve:
                cves[current_cve] = current_info

        return {"metadata": {"test_name": test_name}, "data": cves}

    def read_linux_exploit_suggester(self):
        self.linux_exploit_suggester = self._parse_linux_exploit_suggester("Executing Linux Exploit Suggester", "linux_exploit_suggester")
        return self

    def get_linux_exploit_suggester(self):
        return self.linux_exploit_suggester

    def read_linux_exploit_suggester_2(self):
        self.linux_exploit_suggester_2 = self._parse_linux_exploit_suggester("Executing Linux Exploit Suggester 2", "linux_exploit_suggester_2")
        return self

    def get_linux_exploit_suggester_2(self):
        return self.linux_exploit_suggester_2

    def read_active_ports(self):
        active_ports = []

        with open(self.report, 'r') as file:
            in_section = False

            for line in file:
                if '╔══════════╣ Active Ports' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╚'):
                        continue
                    if line.startswith('╔══════════╣') or line.startswith('══╣'):
                        break
                    parts = line.split()
                    if len(parts) >= 4:
                        port = parts[3].split(':')[-1]
                        active_ports.append(port)

        self.active_ports = {"metadata": {"test_name": "active_ports"}, "data": active_ports}
        return self

    def get_active_ports(self):
        return self.active_ports

    def _read_standard(self, key, test_name):
        parsed_data = []

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '╔══════════╣ ' + key in line or '══╣ ' + key in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╔══════════╣') or line.startswith('══╣'):
                        break
                    if line.startswith('╚'):
                        continue
                    elif line.strip():
                        parsed_data.append(line.strip())

            return {"metadata": {"test_name": test_name}, "data": parsed_data}

    def _read_last_column(self, key, test_name):
        parsed_data = []

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '╔══════════╣ ' + key in line or '══╣ ' + key in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('╔══════════╣') or line.startswith('══╣'):
                        break
                    if line.startswith('╚'):
                        continue
                    elif re.search(r'[A-Za-z]{3}\s+\d{1,2}\s+\d{4}', line):
                        text_after_date = line[re.search(r'[A-Za-z]{3}\s+\d{1,2}\s+\d{4}', line).end():].strip()
                        if text_after_date not in ('.', '..'):
                            parsed_data.append(text_after_date)

            return {"metadata": {"test_name": test_name}, "data": parsed_data}

