import os
import socket
import getpass

import psutil

import lib.output


HOST_FILE = "{}/hosts.txt".format(os.getcwd())
START_POSTGRESQL_PATH = "{}/etc/scripts/start_postgre.sh".format(os.getcwd())
START_APACHE_PATH = "{}/etc/scripts/start_apache.sh".format(os.getcwd())
PLATFORM_PROMPT = "\n{}@\033[36mPLATFORM\033[0m$ ".format(getpass.getuser())
AUTOSPLOIT_PROMPT = "\n\033[31m{}\033[0m@\033[36mautosploit\033[0m# ".format(getpass.getuser())
API_KEYS = {
    "censys": "{}/etc/tokens/censys.key".format(os.getcwd()),
    "shodan": "{}/etc/tokens/shodan.key".format(os.getcwd())
}
API_URLS = {
    "shodan": "https://api.shodan.io/shodan/host/search?key={token}&query={query}",
    "censys": "https://censys.io/api/v1/search/ipv4",
    "zoomeye": (
        "https://api.zoomeye.org/user/login",
        "https://api.zoomeye.org/web/search"
    )
}
AUTOSPLOIT_TERM_OPTS = {
    1: "usage and legal", 2: "gather hosts", 3: "custom hosts",
    4: "add single host", 5: "view gathered hosts", 6: "exploit gathered hosts",
    99: "quit"
}


def validate_ip_addr(provided):
    """
    validate an IP address to see if it is real or not
    """
    try:
        socket.inet_aton(provided)
        return True
    except:
        return False


def check_services(service_name):
    """
    check to see if certain services ar started
    """
    all_processes = set()
    for pid in psutil.pids():
        running_proc = psutil.Process(pid)
        all_processes.add(" ".join(running_proc.cmdline()).strip())
    for proc in list(all_processes):
        if service_name in proc:
            return True
    return False


def write_to_file(data_to_write, filename, mode="a+"):
    """
    write data to a specified file, if it exists, ask to overwrite
    """
    if os.path.exists(filename):
        is_append = lib.output.prompt("would you like to (a)ppend or (o)verwrite the file")
        if is_append == "o":
            mode = "w"
        elif is_append == "a":
            mode = "a+"
        else:
            lib.output.warning("invalid input provided ('{}'), appending to file".format(is_append))
            mode = "a+"
    with open(filename, mode) as log:
        if isinstance(data_to_write, (tuple, set, list)):
            for item in list(data_to_write):
                log.write("{}{}".format(item.strip(), os.linesep))
        else:
            log.write(data_to_write)
    lib.output.info("successfully wrote info to '{}'".format(filename))
    return filename


def load_api_keys(path="{}/etc/tokens".format(os.getcwd())):

    """
    load the API keys from their .key files
    """

    def makedir(dir):
        """
        make the directory if it does not exist
        """
        if not os.path.exists(dir):
            os.mkdir(dir)

    makedir(path)
    for key in API_KEYS.keys():
        if not os.path.isfile(API_KEYS[key]):
            access_token = lib.output.prompt("enter your {} API token".format(key.title()), lowercase=False)
            with open(API_KEYS[key], "a+") as log:
                log.write(access_token.strip())
        else:
            lib.output.info("{} API token loaded from {}".format(key.title(), API_KEYS[key]))
    api_tokens = {
        "censys": open(API_KEYS["censys"]).read(),
        "shodan": open(API_KEYS["shodan"]).read()
    }
    return api_tokens
