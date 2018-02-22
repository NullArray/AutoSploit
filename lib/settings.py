import socket
import getpass


PLATFORM_PROMPT = "\n{}@\033[36mPLATFORM\033[0m$ ".format(getpass.getuser())
AUTOSPLOIT_PROMPT = "\n\033[31m{}\033[0m@\033[36mautosploit\033[0m# ".format(getpass.getuser())


def validate_ip_addr(provided):
    try:
        socket.inet_aton(provided)
        return True
    except:
        return False