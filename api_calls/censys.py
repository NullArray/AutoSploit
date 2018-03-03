"""
using C headers style
"""
from api_calls.api_hook import *

class CensysAPIHook(ApiHook):

    """
    Censys API hook
    """

    def __init__(self, query=None, proxy=None, agent=None, identity=None, token=None, *args):
        ApiHook.__init__(self, query, proxy, agent,token)
        self.id = identity
        self.request_method = requests.post;

    def sent_request(self):
        lib.settings.start_animation("searching Censys with given query '{}'".format(self.query))
        return ApiHook.sent_request(self, API_URLS["censys"], (self.id, self.token))

    def parse_response(self, resp):
        json_data = resp.json()
        for item in json_data["results"]:
            discovered_hosts.add(str(item["ip"]))
        write_to_file(discovered_hosts, self.host_file)
        return True

    def pull_ip(self):
        self.parse_response(self.sent_request())
