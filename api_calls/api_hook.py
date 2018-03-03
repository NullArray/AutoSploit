import requests
import json

import lib.settings
from lib.errors import AutoSploitAPIConnectionError
from lib.settings import (
    HOST_FILE,
    API_URLS,
    write_to_file
)


class ApiHook:

    """
    Abstract API hook
    """

    def __init__(self, query=None, proxy=None, agent=None, token=None):
        self.token = token
        self.query = query
        self.proxy = proxy
        self.user_agent = agent
        self.host_file = HOST_FILE

        self.request_method = None;

    def sent_request(self, urls, auth_turpe=None, params=None, headers=None):
        """
        connect ro the API
        """
        if not headers:
            headers=self.user_agent,
        try:
            return self.request_method(
                urls,
                auth=auth_turpe,
                json={"query": self.query},
                headers=headers,
                params=params,
                proxies=self.proxy
            )
        except Exception as e:
            raise AutoSploitAPIConnectionError(str(e))

    def parse_response(self, resp):
        discovered_hosts = set()
        """
        write ip from response to the file
        """
        pass
    
    def pull_ip(self):
        """
        connect to the API and pull all IP addresses from the provided query
        """
        pass
