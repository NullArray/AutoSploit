import requests

import lib.settings
from lib.errors import AutoSploitAPIConnectionError
from lib.settings import (
    HOST_FILE,
    API_URLS,
    write_to_file
)


class CensysAPIHook(object):

    """
    Censys API hook
    """

    def __init__(self, identity=None, token=None, query=None, proxy=None, agent=None, **kwargs):
        self.id = identity
        self.token = token
        self.query = query
        self.proxy = proxy
        self.user_agent = agent
        self.host_file = HOST_FILE

    def censys(self):
        """
        connect to the Censys API and pull all IP addresses from the provided query
        """
        discovered_censys_hosts = set()
        try:
            lib.settings.start_animation("searching Censys with given query '{}'".format(self.query))
            req = requests.post(
                API_URLS["censys"], auth=(self.id, self.token),
                json={"query": self.query}, headers=self.user_agent,
                proxies=self.proxy
            )
            json_data = req.json()
            for item in json_data["results"]:
                discovered_censys_hosts.add(str(item["ip"]))
            write_to_file(discovered_censys_hosts, self.host_file)
            return True
        except Exception as e:
            raise AutoSploitAPIConnectionError(str(e))