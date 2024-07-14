from bandit.bandit_parser import BanditParser
from gosec.gosec_parser import GosecParser
from linpeas.linpeas_parser import LinpeasParser
from lynis.lynis_parser import LynisParser
import os

bandit_input = os.getenv('BANDIT_INPUT')
bandit_output = os.getenv('BANDIT_OUTPUT')
bandit_html = os.getenv('BANDIT_HTML')
gosec_input = os.getenv('GOSEC_INPUT')
gosec_output = os.getenv('GOSEC_OUTPUT')
gosec_html = os.getenv('GOSEC_HTML')
linpeas_input = os.getenv('LINPEAS_INPUT')
lynis_input = os.getenv('LYNIS_INPUT')

########################################################################

print("Bandit:")
bandit_parser = BanditParser(bandit_input)
bandit_parser.print_json(bandit_parser.get_content())
bandit_parser.print_json(bandit_parser.cwe_targets_aggregation())
bandit_parser.json_to_html(bandit_output, bandit_html)

########################################################################

print("Gosec:")
gosec_parser = GosecParser(gosec_input)
gosec_parser.print_json(gosec_parser.get_content())
gosec_parser.print_json(gosec_parser.cwe_targets_aggregation())
gosec_parser.json_to_html(gosec_output, gosec_html)

########################################################################

print("Linpeas:")
linpeas_parser = LinpeasParser(linpeas_input)

print("Environment")
linpeas_parser.read_environment()
linpeas_parser.print_json(linpeas_parser.get_environment())

print("Analyzing .socket files")
linpeas_parser.print_json(linpeas_parser.read_socket_files().get_socket_files())

print("D-Bus config files")
linpeas_parser.print_json(linpeas_parser.read_dbus_config_files().get_dbus_config_files())

print("Superusers")
linpeas_parser.print_json(linpeas_parser.read_superusers().get_superusers())

print("Users with console")
linpeas_parser.print_json(linpeas_parser.read_users_with_console().get_users_with_console())

print("All users & groups")
linpeas_parser.print_json(linpeas_parser.read_users_and_group().get_users_and_group())

print("Some certificates were found (out limited):")
linpeas_parser.print_json(linpeas_parser.read_certificates().get_certificates())

print("Writable ssh and gpg agents")
linpeas_parser.print_json(linpeas_parser.read_writable_ssh_pgp().get_writable_ssh_pgp())

print("Interesting writable files owned by me or writable by everyone")
linpeas_parser.print_json(linpeas_parser.read_writable_files().get_writable_files())

print(".sh files in path")
linpeas_parser.print_json(linpeas_parser.read_sh_files().get_sh_files())

print("Unexpected in root")
linpeas_parser.print_json(linpeas_parser.read_unexpected_files().get_unexpected_files())

print("SGID")
linpeas_parser.print_json(linpeas_parser.read_sgid().get_sgid())

print("Files (scripts) in /etc/profile.d/")
linpeas_parser.print_json(linpeas_parser.read_script_in_profiles().get_script_in_profiles())

print("SUID - Check easy privesc, exploits and write perms")
linpeas_parser.print_json(linpeas_parser.read_suid().get_suid())

print("Analyzing .service files")
linpeas_parser.print_json(linpeas_parser.read_service().get_service())

print("Capabilities")
linpeas_parser.print_json(linpeas_parser.read_capabilities().get_capabilities())

print("Permissions in init, init.d, systemd, and rc.d")
linpeas_parser.print_json(linpeas_parser.read_permissions().get_permissions())

print("Protections")
linpeas_parser.print_json(linpeas_parser.read_protections().get_protections())

print("Sudo version")
linpeas_parser.print_json(linpeas_parser.read_sudo_version().get_sudo_version())

print("Linux exploit suggester")
linpeas_parser.print_json(linpeas_parser.read_linux_exploit_suggester().get_linux_exploit_suggester())

print("Linux exploit suggester 2")
linpeas_parser.print_json(linpeas_parser.read_linux_exploit_suggester_2().get_linux_exploit_suggester_2())

print("Active Ports")
linpeas_parser.print_json(linpeas_parser.read_active_ports().get_active_ports())

print("Checking sudo tokens")
linpeas_parser.print_json(linpeas_parser.read_sudo_tokens().get_sudo_tokens())

########################################################################

lynis_parser = LynisParser(lynis_input)

print("System data:")
lynis_parser.read_system_data()
lynis_parser.print_json(lynis_parser.get_system_data())

print("Boot and services:")
lynis_parser.print_json(lynis_parser.read_boot_and_services().get_boot_and_services())

print("Kernel:")
lynis_parser.print_json(lynis_parser.read_kernel().get_kernel())

print("Memory and processes:")
lynis_parser.print_json(lynis_parser.read_memory_and_processes().get_memory_and_processes())

print("Users groups and authentication:")
lynis_parser.print_json(lynis_parser.read_users_groups_and_authentication().get_users_groups_and_authentication())

print("Shells:")
lynis_parser.print_json(lynis_parser.read_shell().get_shell())

print("File systems:")
lynis_parser.print_json(lynis_parser.read_file_systems().get_file_systems())

print("USB devices:")
lynis_parser.print_json(lynis_parser.read_usb_devices().get_usb_devices())

print("Storage:")
lynis_parser.print_json(lynis_parser.read_storage().get_storage())

print("NFS:")
lynis_parser.print_json(lynis_parser.read_nfs().get_nfs())

print("Name services:")
lynis_parser.print_json(lynis_parser.read_name_services().get_name_services())

print("Ports and packages:")
lynis_parser.print_json(lynis_parser.read_ports_and_packages().get_ports_and_packages())

print("Networking:")
lynis_parser.print_json(lynis_parser.read_networking().get_networking())

print("Printers and spools:")
lynis_parser.print_json(lynis_parser.read_printers_and_spools().get_printers_and_spools())

print("Email and messaging:")
lynis_parser.print_json(lynis_parser.read_email_and_messaging().get_email_and_messaging())

print("Firewall:")
lynis_parser.print_json(lynis_parser.read_firewall().get_firewall())

print("Webserver:")
lynis_parser.print_json(lynis_parser.read_webserver().get_webserver())

print("ssh:")
lynis_parser.print_json(lynis_parser.read_ssh().get_ssh())

print("SNMP:")
lynis_parser.print_json(lynis_parser.read_snmp().get_snmp())

print("Databases:")
lynis_parser.print_json(lynis_parser.read_databases().get_databases())

print("LDAP:")
lynis_parser.print_json(lynis_parser.read_ldap().get_ldap())

print("PHP:")
lynis_parser.print_json(lynis_parser.read_php().get_php())

print("Squid support:")
lynis_parser.print_json(lynis_parser.read_squid_support().get_squid_support())

print("Logging and files:")
lynis_parser.print_json(lynis_parser.read_logging_and_files().get_logging_and_files())

print("Insecure services:")
lynis_parser.print_json(lynis_parser.read_insecure_services().get_insecure_services())

print("Banners and identification:")
lynis_parser.print_json(lynis_parser.read_banners_and_identification().get_banners_and_identification())

print("Scheduled task:")
lynis_parser.print_json(lynis_parser.read_scheduled_task().get_scheduled_task())

print("Accounting:")
lynis_parser.print_json(lynis_parser.read_accounting().get_accounting())

print("Time and synchronization:")
lynis_parser.print_json(lynis_parser.read_time_and_synchronization().get_time_and_synchronization())

print("Cryptography:")
lynis_parser.print_json(lynis_parser.read_cryptography().get_cryptography())

print("Virtualization:")
lynis_parser.print_json(lynis_parser.read_virtualization().get_virtualization())

print("Containers:")
lynis_parser.print_json(lynis_parser.read_containers().get_containers())

print("Security frameworks:")
lynis_parser.print_json(lynis_parser.read_security_frameworks().get_security_frameworks())

print("File integrity:")
lynis_parser.print_json(lynis_parser.read_file_integrity().get_file_integrity())

print("System tooling:")
lynis_parser.print_json(lynis_parser.read_system_tooling().get_system_tooling())

print("Malware:")
lynis_parser.print_json(lynis_parser.read_malware().get_malware())

print("File permissions:")
lynis_parser.print_json(lynis_parser.read_file_permissions().get_file_permissions())

print("Home directories:")
lynis_parser.print_json(lynis_parser.read_home_directories().get_home_directories())

print("Kernel hardening:")
lynis_parser.print_json(lynis_parser.read_kernel_hardening().get_kernel_hardening())

print("Hardening:")
lynis_parser.print_json(lynis_parser.read_hardening().get_hardening())

print("Custom tests:")
lynis_parser.print_json(lynis_parser.read_custom_tests().get_custom_tests())

print("Results warnings:")
lynis_parser.print_json(lynis_parser.read_results_warnings().get_results_warnings())

print("Results suggestions:")
lynis_parser.print_json(lynis_parser.read_results_suggestions().get_results_suggestions())

print("Scan details:")
lynis_parser.print_json(lynis_parser.read_scan_details().get_scan_details())