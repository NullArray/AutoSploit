import os
import socket
import getpass

import psutil


START_POSTGRESQL_PATH = "{}/etc/scripts/start_postgre.sh".format(os.getcwd())
START_APACHE_PATH = "{}/etc/scripts/start_apache.sh".format(os.getcwd())
PLATFORM_PROMPT = "\n{}@\033[36mPLATFORM\033[0m$ ".format(getpass.getuser())
AUTOSPLOIT_PROMPT = "\n\033[31m{}\033[0m@\033[36mautosploit\033[0m# ".format(getpass.getuser())
AUTOSPLOIT_TERM_OPTS = {
    1: "usage and legal", 2: "gather hosts", 3: "custom hosts",
    4: "add single host", 5: "view gathered hosts", 6: "exploit gathered hosts",
    99: "quit"
}


def validate_ip_addr(provided):
    try:
        socket.inet_aton(provided)
        return True
    except:
        return False


def check_services(service_name):
    all_processes = set()
    for pid in psutil.pids():
        running_proc = psutil.Process(pid)
        all_processes.add(" ".join(running_proc.cmdline()).strip())
    for proc in list(all_processes):
        if service_name in proc:
            return True
    return False