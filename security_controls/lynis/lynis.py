from parser.lynis.lynis_parser import LynisParser
from utils.ssh_client import SshClient
import base64
import os


class Lynis:
    def __init__(self, lynis_version, hardening_index_threshold, output_path, target, target_port, target_username, target_password=None, target_private_key=None, skip_test=None):
        self.lynis_report = dict()
        self.lynis_version = lynis_version
        self.hardening_index_threshold = hardening_index_threshold
        self.output_path = output_path
        self.target = target
        self.target_port = target_port
        self.target_username = target_username
        self.target_password = target_password
        self.target_private_key = target_private_key
        self.skip_test = skip_test

    def execute(self):
        self.download_resources()
        self._skip_test()
        self.lynis_execute()
        self.collect_lynis_output()
        self.clean()
        return self.evaluate_output()

    def download_resources(self):
        ssh_client = self._get_ssh_client()
        ssh_client.connect_ssh()
        ssh_client.send_command(f"sudo wget https://downloads.cisofy.com/lynis/lynis-{self.lynis_version}.tar.gz", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo tar -xzvf lynis-{self.lynis_version}.tar.gz", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo touch lynis_report.txt", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo chmod 777 lynis_report.txt", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo touch lynis_audit.sh", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo chmod 777 lynis_audit.sh", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo touch execute_scripts.py", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo chmod 777 execute_scripts.py", SshClient.onNotZeroExitCodeAction.STOP)

        with open("data/lynis_audit.sh", "r") as file:
            content = file.read()
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            ssh_client.send_command(f"""sudo sh -c 'echo "{encoded_content}" | base64 --decode > lynis_audit.sh'""",
                                    SshClient.onNotZeroExitCodeAction.STOP)

        with open("data/execute_scripts.py", "r") as file:
            content = file.read()
            encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
            ssh_client.send_command(f"""sudo sh -c 'echo "{encoded_content}" | base64 --decode > execute_scripts.py'""",
                                    SshClient.onNotZeroExitCodeAction.STOP)

    def _skip_test(self):
        if len(self.skip_test) > 0:
            ssh_client = self._get_ssh_client()
            ssh_client.connect_ssh()
            for test in self.skip_test:
                ssh_client.send_command(f"""sudo sh -c 'echo "skip-test={test}" >> /lynis/default.prf'""",
                                        SshClient.onNotZeroExitCodeAction.STOP)

    def lynis_execute(self):
        ssh_client = self._get_ssh_client()
        ssh_client.connect_ssh()
        out_raw=ssh_client.send_command(f"sudo python3 execute_scripts.py", SshClient.onNotZeroExitCodeAction.STOP)
        print(out_raw['stdout'])

    def collect_lynis_output(self):
        ssh_client = self._get_ssh_client()
        ssh_client.connect_ssh()
        ssh_client.get_file(os.getenv('TEMP_PATH')+"lynis_report.txt", "lynis_report.txt")
        lynis_parser = LynisParser(os.getenv('TEMP_PATH')+"lynis_report.txt")
        system_data = lynis_parser.read_system_data().get_system_data()
        boot_and_services = lynis_parser.read_boot_and_services().get_boot_and_services()
        kernel = lynis_parser.read_kernel().get_kernel()
        memory_and_processes = lynis_parser.read_memory_and_processes().get_memory_and_processes()
        users_groups_and_authentication = lynis_parser.read_users_groups_and_authentication().get_users_groups_and_authentication()
        shell = lynis_parser.read_shell().get_shell()
        file_systems = lynis_parser.read_file_systems().get_file_systems()
        usb_devices = lynis_parser.read_usb_devices().get_usb_devices()
        storage = lynis_parser.read_storage().get_storage()
        nfs = lynis_parser.read_nfs().get_nfs()
        name_services = lynis_parser.read_name_services().get_name_services()
        ports_and_packages = lynis_parser.read_ports_and_packages().get_ports_and_packages()
        networking = lynis_parser.read_networking().get_networking()
        printers_and_spools = lynis_parser.read_printers_and_spools().get_printers_and_spools()
        email_and_messaging = lynis_parser.read_email_and_messaging().get_email_and_messaging()
        firewall = lynis_parser.read_firewall().get_firewall()
        webserver = lynis_parser.read_webserver().get_webserver()
        ssh = lynis_parser.read_ssh().get_ssh()
        snmp = lynis_parser.read_snmp().get_snmp()
        databases = lynis_parser.read_databases().get_databases()
        ldap = lynis_parser.read_ldap().get_ldap()
        php = lynis_parser.read_php().get_php()
        squid_support = lynis_parser.read_squid_support().get_squid_support()
        logging_and_files = lynis_parser.read_logging_and_files().get_logging_and_files()
        insecure_services = lynis_parser.read_insecure_services().get_insecure_services()
        banners_and_identification = lynis_parser.read_banners_and_identification().get_banners_and_identification()
        scheduled_task = lynis_parser.read_scheduled_task().get_scheduled_task()
        accounting = lynis_parser.read_accounting().get_accounting()
        time_and_synchronization = lynis_parser.read_time_and_synchronization().get_time_and_synchronization()
        cryptography = lynis_parser.read_cryptography().get_cryptography()
        virtualization = lynis_parser.read_virtualization().get_virtualization()
        containers = lynis_parser.read_containers().get_containers()
        security_frameworks = lynis_parser.read_security_frameworks().get_security_frameworks()
        file_integrity = lynis_parser.read_file_integrity().get_file_integrity()
        system_tooling = lynis_parser.read_system_tooling().get_system_tooling()
        malware = lynis_parser.read_malware().get_malware()
        file_permissions = lynis_parser.read_file_permissions().get_file_permissions()
        home_directories = lynis_parser.read_home_directories().get_home_directories()
        kernel_hardening = lynis_parser.read_kernel_hardening().get_kernel_hardening()
        hardening = lynis_parser.read_hardening().get_hardening()
        custom_tests = lynis_parser.read_custom_tests().get_custom_tests()
        results_warnings = lynis_parser.read_results_warnings().get_results_warnings()
        results_suggestions = lynis_parser.read_results_suggestions().get_results_suggestions()
        scan_details = lynis_parser.read_scan_details().get_scan_details()
        self.lynis_report = {
            "Lynis": [system_data, boot_and_services, kernel, memory_and_processes, users_groups_and_authentication,
                      shell, file_systems, usb_devices, storage, nfs, name_services, ports_and_packages, networking,
                      printers_and_spools, email_and_messaging, firewall, webserver, ssh, snmp, databases, ldap,
                      php,
                      squid_support, logging_and_files, insecure_services, banners_and_identification,
                      scheduled_task,
                      accounting, time_and_synchronization, cryptography, virtualization, containers,
                      security_frameworks,
                      file_integrity, system_tooling, malware, file_permissions, home_directories, kernel_hardening,
                      hardening, custom_tests, results_warnings, results_suggestions, scan_details]}

        lynis_parser.save_json(os.getenv('REPORT_PATH')+self.output_path)

    def evaluate_output(self):
        hardening_index = None
        for test in self.lynis_report['Lynis']:
            if test['metadata']['test_name'] == 'scan_details':
                hardening_index = int(test['data']['Hardening index'])
                break

        if hardening_index < int(self.hardening_index_threshold):
            return 1
        else:
            return 0

    def clean(self):
        ssh_client = self._get_ssh_client()
        ssh_client.connect_ssh()
        ssh_client.send_command(f"sudo rm -rf lynis/", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo rm lynis*", SshClient.onNotZeroExitCodeAction.STOP)
        ssh_client.send_command(f"sudo rm execute_scripts.py", SshClient.onNotZeroExitCodeAction.STOP)

    def _get_ssh_client(self) -> SshClient:
        ssh_client: SshClient = SshClient(
            host=self.target,
            port=self.target_port,
            username=self.target_username,
            password=self.target_password,
            private_key=self.target_private_key,
            private_key_passphrase=None)

        return ssh_client
