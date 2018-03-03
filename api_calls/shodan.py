"""
using C headers style
"""
from api_calls.api_hook import *

class ShodanAPIHook(ApiHook):
    """
    Shodan API hook, saves us from having to install another dependency
    """

    def __init__(self,  query=None, proxy=None, agent=None, token=None, *args):
        ApiHook.__init__(self, query, proxy, agent, token)

    def sent_request(self):
        lib.settings.start_animation("searching Shodan with given query '{}'".format(self.query))
        return ApiHook.sent_request(
                self,
                API_URLS["shodan"].format(query=self.query, token=self.token))
 
    def parse_response(self, resp):
        json_data = json.loads(resp.content)
        for match in json_data["matches"]:
            discovered_shodan_hosts.add(match["ip_str"])
        write_to_file(discovered_shodan_hosts, self.host_file)
        return True

    def pull_IP(self):
        self.parse_response(self.sent_request())
