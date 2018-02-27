import os
import sys
import time
import socket
import getpass
import tempfile
# import subprocess

import psutil

import lib.output
import lib.banner


HOST_FILE = "{}/hosts.txt".format(os.getcwd())
USAGE_AND_LEGAL_PATH = "{}/etc/text_files/general".format(os.getcwd())
START_POSTGRESQL_PATH = "{}/etc/scripts/start_postgre.sh".format(os.getcwd())
START_APACHE_PATH = "{}/etc/scripts/start_apache.sh".format(os.getcwd())
QUERY_FILE_PATH = tempfile.NamedTemporaryFile(delete=False).name
PLATFORM_PROMPT = "\n{}@\033[36mPLATFORM\033[0m$ ".format(getpass.getuser())
AUTOSPLOIT_PROMPT = "\n\033[31m{}\033[0m@\033[36mautosploit\033[0m# ".format(getpass.getuser())
API_KEYS = {
    "censys": ("{}/etc/tokens/censys.key".format(os.getcwd()), "{}/etc/tokens/censys.id".format(os.getcwd())),
    "shodan": ("{}/etc/tokens/shodan.key".format(os.getcwd()), )
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

stop_animation = False


def validate_ip_addr(provided):
    """
    validate an IP address to see if it is real or not
    """
    not_acceptable = ("0.0.0.0", "127.0.0.1", "255.255.255.255")
    if provided not in not_acceptable:
        try:
            socket.inet_aton(provided)
            return True
        except:
            return False
    else:
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
    global stop_animation

    if os.path.exists(filename):
        stop_animation = True
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
        if not os.path.isfile(API_KEYS[key][0]):
            access_token = lib.output.prompt("enter your {} API token".format(key.title()), lowercase=False)
            if key.lower() == "censys":
                identity = lib.output.prompt("enter your {} ID".format(key.title()), lowercase=False)
                with open(API_KEYS[key][1], "a+") as log:
                    log.write(identity)
            with open(API_KEYS[key][0], "a+") as log:
                log.write(access_token.strip())
        else:
            lib.output.info("{} API token loaded from {}".format(key.title(), API_KEYS[key][0]))
    api_tokens = {
        "censys": (open(API_KEYS["censys"][0]).read(), open(API_KEYS["censys"][1]).read()),
        "shodan": (open(API_KEYS["shodan"][0]).read(), )
    }
    return api_tokens


def cmdline(command):
    """
    Function that allows us to store system command output in a variable.
    We'll change this later in order to solve the potential security
    risk that arises when passing untrusted input to the shell.

    I intend to have the issue resolved by Version 1.5.0.
    """

    os.system(command)
    '''process = subprocess.call(
        args=" ".join(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True
    )
    return process'''


def check_for_msf():
    in_env = os.getenv("msfconsole", False)
    if not in_env:
        return False


def logo():
    """
    display a random banner from the banner.py file
    """
    print(lib.banner.banner_main())


def animation(text):
    """
    display an animation while working, this will be
    single threaded so that it will not screw with the
    current running process
    """
    global stop_animation
    i = 0
    while not stop_animation:
        if stop_animation is True:
            print("\n")
        temp_text = list(text)
        if i >= len(temp_text):
            i = 0
        temp_text[i] = temp_text[i].upper()
        temp_text = ''.join(temp_text)
        sys.stdout.write("\033[96m\033[1m{}...\r\033[0m".format(temp_text))
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)


def start_animation(text):
    import threading

    t = threading.Thread(target=animation, args=(text,))
    t.daemon = True
    t.start()