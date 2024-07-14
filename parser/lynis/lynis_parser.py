import re
import json


class LynisParser:
    def __init__(self, report_file_path):
        self.report = report_file_path
        self.system_data = dict
        self.boot_and_services = dict
        self.kernel = dict
        self.memory_and_processes = dict
        self.users_groups_and_authentication = dict
        self.shell = dict
        self.file_systems = dict
        self.usb_devices = dict
        self.storage = dict
        self.nfs = dict
        self.name_services = dict
        self.ports_and_packages = dict
        self.networking = dict
        self.printers_and_spools = dict
        self.email_and_messaging = dict
        self.firewall = dict
        self.webserver = dict
        self.ssh = dict
        self.snmp = dict
        self.databases = dict
        self.ldap = dict
        self.php = dict
        self.squid_support = dict
        self.logging_and_files = dict
        self.insecure_services = dict
        self.banners_and_identification = dict
        self.scheduled_task = dict
        self.accounting = dict
        self.time_and_synchronization = dict
        self.cryptography = dict
        self.virtualization = dict
        self.containers = dict
        self.security_frameworks = dict
        self.file_integrity = dict
        self.system_tooling = dict
        self.malware = dict
        self.file_permissions = dict
        self.home_directories = dict
        self.kernel_hardening = dict
        self.hardening = dict
        self.custom_tests = dict
        self.results_warnings = dict
        self.results_suggestions = dict
        self.scan_details = dict
        self._sanitize_file()

    def _sanitize_file(self):
        with open(self.report, 'r') as f:
            file_content = f.read()

        cleaned_content = re.sub(r'\x1b\[[0-9]+C', '', file_content)

        with open(self.report, 'w') as f:
            f.write(cleaned_content)

    def print_json(self, json_file):
        print(json.dumps(json_file, indent=4))
        print("\n")

    def save_json(self, json_file):
        report = {
            "Lynis": [self.system_data, self.boot_and_services, self.kernel, self.memory_and_processes, self.users_groups_and_authentication,
                      self.shell, self.file_systems, self.usb_devices, self.storage, self.nfs, self.name_services, self.ports_and_packages, self.networking,
                      self.printers_and_spools, self.email_and_messaging, self.firewall, self.webserver, self.ssh, self.snmp, self.databases, self.ldap,
                      self.php,
                      self.squid_support, self.logging_and_files, self.insecure_services, self.banners_and_identification,
                      self.scheduled_task,
                      self.accounting, self.time_and_synchronization, self.cryptography, self.virtualization, self.containers,
                      self.security_frameworks,
                      self.file_integrity, self.system_tooling, self.malware, self.file_permissions, self.home_directories, self.kernel_hardening,
                      self.hardening, self.custom_tests, self.results_warnings, self.results_suggestions, self.scan_details]}

        with open(json_file, 'w') as file:
            json.dump(report, file, indent=4)

    def read_system_data(self):
        pattern = r"Program version:\s+(.*?)\n\s+Operating system:\s+(.*?)\n\s+Operating system name:\s+(.*?)\n\s+Operating system version:\s+(.*?)\n\s+Kernel version:\s+(.*?)\n\s+Hardware platform:\s+(.*?)\n\s+Hostname:\s+(.*?)\n"

        parsed_data = {}

        with open(self.report, 'r') as file:
            content = file.read()

            match = re.search(pattern, content)

            if match:
                program_version = match.group(1)
                os_name = match.group(2)
                os_distro = match.group(3)
                os_version = match.group(4)
                kernel_version = match.group(5)
                hardware_platform = match.group(6)
                hostname = match.group(7)

                parsed_data['Program version'] = program_version
                parsed_data['Operating system'] = os_name
                parsed_data['Operating system name'] = os_distro
                parsed_data['Operating system version'] = os_version
                parsed_data['Kernel version'] = kernel_version
                parsed_data['Hardware platform'] = hardware_platform
                parsed_data['Hostname'] = hostname

        self.system_data = {"metadata": {"test_name": "system_data"}, "data": parsed_data}
        return self

    def get_system_data(self):
        return self.system_data

    def read_boot_and_services(self):
        parsed_data = {}
        warnings = []
        running_services = []
        enabled_services = []
        systemd_analyze_security = {}
        index = 0

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_boot_section = False
            for line in file_content:
                index += 1

                if '[+] Boot and services' in line:
                    in_boot_section = True
                    continue

                if in_boot_section:
                    if line.startswith('[+]'):
                        break
                    if '[WARNING]' in line:
                        warnings.append(line.strip())
                    elif 'Service Manager' in line:
                        parsed_data['Service Manager'] = line.split('[', 1)[1].split(']')[0].strip()
                    elif 'Checking UEFI boot' in line:
                        parsed_data['Checking UEFI boot'] = line.split('[', 1)[1].split(']')[0].strip()
                    elif 'Boot loader' in line:
                        parsed_data['Boot loader'] = line.split('[', 1)[1].split(']')[0].strip()
                    elif 'Check running services (systemctl)' in line:
                        running_services.append(line.split('[', 1)[1].split(']')[0].strip())
                        result = re.search(r'found (\d+) running', file_content[index])
                        if result:
                            running_services.append(int(result.group(1)))
                    elif 'Check enabled services at boot (systemctl)' in line:
                        enabled_services.append(line.split('[', 1)[1].split(']')[0].strip())
                        result = re.search(r'found (\d+) enabled', file_content[index])
                        if result:
                            enabled_services.append(int(result.group(1)))
                    elif 'Check startup files (permissions)' in line:
                        parsed_data['Check startup files (permissions)'] = line.split('[', 1)[1].split(']')[0].strip()
                    elif '.service' in line:
                        service_name = line.strip().split(':')[0].lstrip('- ')
                        systemd_analyze_security[service_name] = line.split('[', 1)[1].split(']')[0].strip()

            parsed_data['Check running services (systemctl)'] = running_services
            parsed_data['Check enabled services at boot (systemctl)'] = enabled_services
            parsed_data['systemd-analyze security'] = systemd_analyze_security
            parsed_data['Warnings'] = warnings

            self.boot_and_services = {"metadata": {"test_name": "boot_and_services"}, "data": parsed_data}
            return self

    def get_boot_and_services(self):
        return self.boot_and_services

    def read_kernel(self):
        self.kernel = self._read_standard("Kernel", "kernel")
        return self

    def get_kernel(self):
        return self.kernel

    def read_memory_and_processes(self):
        self.memory_and_processes = self._read_standard("Memory and Processes", "memory_and_processes")
        return self

    def get_memory_and_processes(self):
        return self.memory_and_processes

    def read_users_groups_and_authentication(self):
        self.users_groups_and_authentication = self._read_standard("Users, Groups and Authentication", "users_groups_and_authentication")
        return self

    def get_users_groups_and_authentication(self):
        return self.users_groups_and_authentication

    def read_shell(self):
        parsed_data = {}
        warnings = []
        shell_found = []
        index = 0

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                index += 1
                if '[+] Shells' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('[+]'):
                        break
                    if '[WARNING]' in line:
                        warnings.append(line.strip())
                    elif 'Checking shells from /etc/shells' in line:
                        result = re.search(r'Result: found (\d+) shells', file_content[index])
                        if result:
                            shell_found.append(int(result.group(1)))
                        result = re.search(r'valid shells: (\d+)', file_content[index])
                        if result:
                            shell_found.append(int(result.group(1)))
                    elif 'Session timeout settings/tools' in line:
                        parsed_data['Session timeout settings/tools'] = line.split('[', 1)[1].split(']')[0].strip()
                    elif 'Checking default umask in /etc/bash.bashrc' in line:
                        parsed_data['Checking default umask in /etc/bash.bashrc'] = line.split('[', 1)[1].split(']')[0].strip()
                    elif 'Checking default umask in /etc/profile' in line:
                        parsed_data['Checking default umask in /etc/profile'] = line.split('[', 1)[1].split(']')[0].strip()


            parsed_data['Shells found'] = shell_found
            parsed_data['Warnings'] = warnings

            self.shell = {"metadata": {"test_name": "shell"}, "data": parsed_data}
            return self

    def get_shell(self):
        return self.shell

    def read_file_systems(self):
        parsed_data = {}
        warnings = []
        mount_options = {}

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '[+] File systems' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('[+]'):
                        break
                    if '[WARNING]' in line:
                        warnings.append(line.strip())
                    elif '[' in line and ']' in line:
                        key = line.split('[', 1)[0].strip().lstrip('- ')
                        value = line.split('[', 1)[1].split(']')[0].strip()
                        parsed_data[key] = value
                    elif 'Total' in line:
                        result = re.search(r'nodev:(\d+) noexec:(\d+) nosuid:(\d+) (.+): (\d+) of total (\d+)', line)
                        if result:
                            nodev = int(result.group(1))
                            noexec = int(result.group(2))
                            nosuid = int(result.group(3))
                            other_option = result.group(4)
                            other_count = int(result.group(5))
                            total_count = int(result.group(6))

                            mount_options['nodev'] = nodev
                            mount_options['noexec'] = noexec
                            mount_options['nosuid'] = nosuid
                            mount_options[other_option] = f"{other_count} of total {total_count}"

            parsed_data['Mount options'] = mount_options
            parsed_data['Warnings'] = warnings

            self.file_systems = {"metadata": {"test_name": "file_systems"}, "data": parsed_data}
            return self

    def get_file_systems(self):
        return self.file_systems

    def read_usb_devices(self):
        self.usb_devices = self._read_standard("USB Devices", "usb_devices")
        return self

    def get_usb_devices(self):
        return self.usb_devices

    def read_storage(self):
        self.storage = self._read_standard("Storage", "storage")
        return self

    def get_storage(self):
        return self.storage

    def read_nfs(self):
        self.nfs = self._read_standard("NFS", "nfs")
        return self

    def get_nfs(self):
        return self.nfs

    def read_name_services(self):
        self.name_services = self._read_standard("Name services", "name_services")
        return self

    def get_name_services(self):
        return self.name_services

    def read_ports_and_packages(self):
        self.ports_and_packages = self._read_standard("Ports and packages", "ports_and_packages")
        return self

    def get_ports_and_packages(self):
        return self.ports_and_packages

    def read_networking(self):
        self.networking = self._read_standard("Networking", "networking")
        return self

    def get_networking(self):
        return self.networking

    def read_printers_and_spools(self):
        self.printers_and_spools = self._read_standard("Printers and Spools", "printers_and_spools")
        return self

    def get_printers_and_spools(self):
        return self.printers_and_spools

    def read_email_and_messaging(self):
        self.email_and_messaging = self._read_standard("Software: e-mail and messaging", "email_and_messaging")
        return self

    def get_email_and_messaging(self):
        return self.email_and_messaging

    def read_firewall(self):
        parsed_data = {}
        warnings = []
        iptables_warnings = []
        iptables = []

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '[+] Software: firewalls' in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('[+]'):
                        break
                    if '[WARNING]' in line:
                        warnings.append(line.strip())
                    elif '# Warning' in line:
                        iptables_warnings.append(line.strip())
                    elif 'iptables' in line:
                        iptables.append(line.strip())
                    elif '[' in line and ']' in line:
                        key = line.split('[', 1)[0].strip().lstrip('- ')
                        value = line.split('[', 1)[1].split(']')[0].strip()
                        parsed_data[key] = value

            parsed_data['iptables warnings'] = iptables_warnings
            parsed_data['iptables'] = iptables
            parsed_data['Warnings'] = warnings

            self.firewall = {"metadata": {"test_name": "firewall"}, "data": parsed_data}
            return self

    def get_firewall(self):
        return self.firewall

    def read_webserver(self):
        self.webserver = self._read_standard("Software: webserver", "webserver")
        return self

    def get_webserver(self):
        return self.webserver

    def read_ssh(self):
        self.ssh = self._read_standard("SSH Support", "ssh")
        return self

    def get_ssh(self):
        return self.ssh

    def read_snmp(self):
        self.snmp = self._read_standard("SNMP Support", "snmp")
        return self

    def get_snmp(self):
        return self.snmp

    def read_databases(self):
        self.databases = self._read_standard("Databases", "databases")
        return self

    def get_databases(self):
        return self.databases

    def read_ldap(self):
        self.ldap = self._read_standard("LDAP Services", "ldap")
        return self

    def get_ldap(self):
        return self.ldap

    def read_php(self):
        self.php = self._read_standard("PHP", "php")
        return self

    def get_php(self):
        return self.php

    def read_squid_support(self):
        self.squid_support = self._read_standard("Squid Support", "squid_support")
        return self

    def get_squid_support(self):
        return self.squid_support

    def read_logging_and_files(self):
        self.logging_and_files = self._read_standard("Logging and files", "logging_and_files")
        return self

    def get_logging_and_files(self):
        return self.logging_and_files

    def read_insecure_services(self):
        self.insecure_services = self._read_standard("Insecure services", "insecure_services")
        return self

    def get_insecure_services(self):
        return self.insecure_services

    def read_banners_and_identification(self):
        self.banners_and_identification = self._read_standard("Banners and identification", "banners_and_identification")
        return self

    def get_banners_and_identification(self):
        return self.banners_and_identification

    def read_scheduled_task(self):
        self.scheduled_task = self._read_standard("Scheduled tasks", "scheduled_task")
        return self

    def get_scheduled_task(self):
        return self.scheduled_task

    def read_accounting(self):
        self.accounting = self._read_standard("Accounting", "accounting")
        return self

    def get_accounting(self):
        return self.accounting

    def read_time_and_synchronization(self):
        self.time_and_synchronization = self._read_standard("Time and Synchronization", "time_and_synchronization")
        return self

    def get_time_and_synchronization(self):
        return self.time_and_synchronization

    def read_cryptography(self):
        self.cryptography = self._read_standard("Cryptography", "cryptography")
        return self

    def get_cryptography(self):
        return self.cryptography

    def read_virtualization(self):
        self.virtualization = self._read_standard("Virtualization", "virtualization")
        return self

    def get_virtualization(self):
        return self.virtualization

    def read_containers(self):
        self.containers = self._read_standard("Containers", "containers")
        return self

    def get_containers(self):
        return self.containers

    def read_security_frameworks(self):
        self.security_frameworks = self._read_standard("Security frameworks", "security_frameworks")
        return self

    def get_security_frameworks(self):
        return self.security_frameworks

    def read_file_integrity(self):
        self.file_integrity = self._read_standard("Software: file integrity", "file_integrity")
        return self

    def get_file_integrity(self):
        return self.file_integrity

    def read_system_tooling(self):
        self.system_tooling = self._read_standard("Software: System tooling", "system_tooling")
        return self

    def get_system_tooling(self):
        return self.system_tooling

    def read_malware(self):
        self.malware = self._read_standard("Software: Malware", "malware")
        return self

    def get_malware(self):
        return self.malware

    def read_file_permissions(self):
        self.file_permissions = self._read_standard("File Permissions", "file_permissions")
        return self

    def get_file_permissions(self):
        return self.file_permissions

    def read_home_directories(self):
        self.home_directories = self._read_standard("Home directories", "home_directories")
        return self

    def get_home_directories(self):
        return self.home_directories

    def read_kernel_hardening(self):
        self.kernel_hardening = self._read_standard("Kernel Hardening", "kernel_hardening")
        return self

    def get_kernel_hardening(self):
        return self.kernel_hardening

    def read_hardening(self):
        self.hardening = self._read_standard("Hardening", "hardening")
        return self

    def get_hardening(self):
        return self.hardening

    def read_custom_tests(self):
        self.custom_tests = self._read_standard("Custom tests", "custom_tests")
        return self

    def get_custom_tests(self):
        return self.custom_tests

    def read_results_warnings(self):
        lynis_warnings = []

        with open(self.report, 'r') as file:
            file_content = file.read()

            warning_results = re.findall(r'! (.+?)\n\s+(https?://\S+)', file_content, re.DOTALL)

            for warning in warning_results:
                title = warning[0].strip()
                link = warning[1].strip()

                lynis_warnings.append({
                    "Title": title,
                    "Link": link
                })

        self.results_warnings = {"metadata": {"test_name": "lynis_warnings"}, "data": lynis_warnings}
        return self

    def get_results_warnings(self):
        return self.results_warnings

    def read_results_suggestions(self):
        lynis_suggestions = []

        with open(self.report, 'r') as file:
            file_content = file.read()

            suggestion_results = re.findall(r'\* (.+?)\n\s*(?:- Details\s*: (.+?)\n)?\s*(https?://\S+)', file_content,
                                            re.DOTALL)

            for suggestion in suggestion_results:
                title = suggestion[0].strip()
                details = suggestion[1].strip() if suggestion[1] else ""
                link = suggestion[2].strip()

                lynis_suggestions.append({
                    "Title": title,
                    "Details": details,
                    "Link": link
                })

        self.results_suggestions = {"metadata": {"test_name": "lynis_suggestions"}, "data": lynis_suggestions}
        return self

    def get_results_suggestions(self):
        return self.results_suggestions

    def read_scan_details(self):
        scan_details = {}

        with open(self.report, 'r') as file:
            file_content = file.read()

            scan_details["Hardening index"] = re.search(r'Hardening index : (\d+)', file_content).group(1)
            scan_details["Tests performed"] = re.search(r'Tests performed : (\d+)', file_content).group(1)
            scan_details["Plugins enabled"] = re.search(r'Plugins enabled : (\d+)', file_content).group(1)
            scan_details["Firewall"] = re.search(r'Firewall\s*\[([VX?])\]', file_content).group(1)
            scan_details["Malware scanner"] = re.search(r'Malware scanner\s*\[([VX?])\]', file_content).group(1)

            scan_modes_result = re.search(
                r'Normal \[([VX ])\]\s*Forensics \[([VX ])\]\s*Integration \[([VX ])\]\s*Pentest \[([VX ])\]',
                file_content)
            if scan_modes_result:
                scan_details["Scan modes"] = {
                    "Normal": scan_modes_result.group(1).strip(),
                    "Forensics": scan_modes_result.group(2).strip(),
                    "Integration": scan_modes_result.group(3).strip(),
                    "Pentest": scan_modes_result.group(4).strip()
                }

            scan_details["Compliance status"] = re.search(r'Compliance status\s*\[([VX?])\]', file_content).group(1)
            scan_details["Security audit"] = re.search(r'Security audit\s*\[([VX?])\]', file_content).group(1)
            scan_details["Vulnerability scan"] = re.search(r'Vulnerability scan\s*\[([VX?])\]', file_content).group(1)

        self.scan_details = {"metadata": {"test_name": "scan_details"}, "data": scan_details}
        return self

    def get_scan_details(self):
        return self.scan_details

    def _read_standard(self, key, test_name):
        parsed_data = {}
        warnings = []

        with open(self.report, 'r') as file:
            file_content = file.readlines()

            in_section = False
            for line in file_content:
                if '[+] ' + key in line:
                    in_section = True
                    continue

                if in_section:
                    if line.startswith('[+]'):
                        break
                    if '[WARNING]' in line:
                        warnings.append(line.strip())

                    elif '[' in line and ']' in line:
                        key = line.split('[', 1)[0].strip().lstrip('- ')
                        value = line.split('[', 1)[1].split(']')[0].strip()
                        parsed_data[key] = value

            parsed_data['Warnings'] = warnings

            return {"metadata": {"test_name": test_name}, "data": parsed_data}
