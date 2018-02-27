import json

import requests

from lib.errors import AutoSploitAPIConnectionError
from lib.output import (
    error,
    info
)
from lib.settings import (
    API_URLS,
    HOST_FILE,
    write_to_file
)


class ShodanAPIHook(object):

    """
    Shodan API hook, saves us from having to install another dependency
    """

    def __init__(self, token, query, proxy=None):
        self.token = token
        self.query = query
        self.proxy = proxy
        self.host_file = HOST_FILE

    def shodan(self):
        """
        connect to the API and grab all IP addresses associated with the provided query
        """
        info("searching Shodan with given query '{}'".format(self.query))
        discovered_shodan_hosts = set()
        try:
            req = requests.get(API_URLS["shodan"].format(query=self.query, token=self.token))
            json_data = json.loads(req.content)
            for match in json_data["matches"]:
                discovered_shodan_hosts.add(match["ip_str"])
            write_to_file(discovered_shodan_hosts, self.host_file)
            return True
        except Exception as e:
            error(AutoSploitAPIConnectionError(str(e)))
            return False


