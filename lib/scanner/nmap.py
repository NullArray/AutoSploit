"""

*********************************************************************************************
*                          NOTICE FROM AUTOSPLOIT DEVELOPERS                                *
*********************************************************************************************
* this is basically an exact copy of                                                        *
* `https://github.com/komand/python-nmap/blob/master/nmap/nmap.py` that has been modified   *
* to better fit into autosploits development. There has been very minimal changes to it     *
* and it still basically functions the exact same way                                       *
*********************************************************************************************


ORIGINAL INFO:
--------------
nmap.py - version and date, see below
Source code : https://bitbucket.org/xael/python-nmap
Author :
* Alexandre Norman - norman at xael.org
Contributors:
* Steve 'Ashcrow' Milner - steve at gnulinux.net
* Brian Bustin - brian at bustin.us
* old.schepperhand
* Johan Lundberg
* Thomas D. maaaaz
* Robert Bost
* David Peltier
Licence: GPL v3 or any later version for python-nmap
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
**************
IMPORTANT NOTE
**************
The Nmap Security Scanner used by python-nmap is distributed
under it's own licence that you can find at https://svn.nmap.org/nmap/COPYING
Any redistribution of python-nmap along with the Nmap Security Scanner
must conform to the Nmap Security Scanner licence

__author__ = 'Alexandre Norman (norman@xael.org)'
__version__ = '0.6.2'
__last_modification__ = '2017.01.07'
"""

import os
import json
import subprocess

from xml.etree import ElementTree

import lib.jsonize
import lib.errors
import lib.output
import lib.settings


def parse_nmap_args(args):
    """
    parse the provided arguments and ask if they aren't in the `known` arguments list
    """
    runnable_args = []
    known_args = [a.strip() for a in open(lib.settings.NMAP_OPTIONS_PATH).readlines()]
    for arg in args:
        if " " in arg:
            tmparg = arg.split(" ")[0]
        else:
            tmparg = arg
        if tmparg in known_args:
            runnable_args.append(arg)
        else:
            choice = lib.output.prompt(
                "argument: '{}' is not in the list of 'known' nmap arguments, "
                "do you want to use it anyways[y/N]".format(arg)
            )
            if choice.lower() == "y":
                runnable_args.append(tmparg)
    return runnable_args


def write_data(host, output, is_xml=True):
    """
    dump XML data to a file
    """
    if not os.path.exists(lib.settings.NMAP_XML_OUTPUT_BACKUP if is_xml else lib.settings.NMAP_JSON_OUTPUT_BACKUP):
        os.makedirs(lib.settings.NMAP_XML_OUTPUT_BACKUP if is_xml else lib.settings.NMAP_JSON_OUTPUT_BACKUP)
    file_path = "{}/{}_{}.{}".format(
        lib.settings.NMAP_XML_OUTPUT_BACKUP if is_xml else lib.settings.NMAP_JSON_OUTPUT_BACKUP,
        str(host), lib.jsonize.random_file_name(length=10), "xml" if is_xml else "json"
    )
    with open(file_path, 'a+') as results:
        if is_xml:
            results.write(output)
        else:
            json.dump(output, results, indent=4)
    return file_path


def find_nmap(search_paths):
    """
    check if nmap is on the system
    """
    for path in search_paths:
        try:
            _ = subprocess.Popen([path, '-V'], bufsize=10000, stdout=subprocess.PIPE, close_fds=True)
        except OSError:
            pass
        else:
            return path
    raise lib.errors.NmapNotFoundException


def do_scan(host, nmap_path, ports=None, arguments=None):
    """
    perform the nmap scan
    """
    if arguments is None:
        lib.output.misc_info("using default scan arguments")
        arguments = [
            "-sF", "-Pn", "-sV",
            "-O", "-F", "--reason",
            "-vvv"
        ]
    launch_arguments = [
        nmap_path, '-oX', '-', host,
        '-p ' + ports if ports is not None else "",
    ] + arguments
    to_launch = []
    for item in launch_arguments:
        if not item == "":
            to_launch.append(item)
    lib.output.info("launching nmap scan against {} ({})".format(host, " ".join(to_launch)))
    process = subprocess.Popen(
        launch_arguments, bufsize=10000, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output, error = process.communicate()
    output_data = bytes.decode(output)
    nmap_error = bytes.decode(error)
    nmap_error_tracestack = []
    nmap_warn_tracestack = []
    if len(nmap_error) > 0:
        for line in nmap_error.split(os.linesep):
            if len(line) != 0:
                if lib.settings.NMAP_ERROR_REGEX_WARNING.search(line) is not None:
                    nmap_warn_tracestack.append(line + os.linesep)
                else:
                    nmap_error_tracestack.append(line + os.linesep)
    write_data(host, output_data, is_xml=True)
    return output_data, "".join(nmap_warn_tracestack), "".join(nmap_error_tracestack)


# copy pasta :DD
# https://github.com/komand/python-nmap/blob/master/nmap/nmap.py#L273
def parse_xml_output(output, warnings, error):
    """
    Analyses NMAP xml scan ouput
    May raise PortScannerError exception if nmap output was not xml
    Test existance of the following key to know if something went wrong : ['nmap']['scaninfo']['error']
    If not present, everything was ok.
    :param nmap_xml_output: xml string to analyse
    :returns: scan_result as dictionnary
    """
    # nmap xml output looks like :
    # <host starttime="1267974521" endtime="1267974522">
    #   <status state="up" reason="user-set"/>
    #   <address addr="192.168.1.1" addrtype="ipv4" />
    #   <hostnames><hostname name="neufbox" type="PTR" /></hostnames>
    #   <ports>
    #     <port protocol="tcp" portid="22">
    #       <state state="filtered" reason="no-response" reason_ttl="0"/>
    #       <service name="ssh" method="table" conf="3" />
    #     </port>
    #     <port protocol="tcp" portid="25">
    #       <state state="filtered" reason="no-response" reason_ttl="0"/>
    #       <service name="smtp" method="table" conf="3" />
    #     </port>
    #   </ports>
    #   <hostscript>
    #    <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
    #    <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
    #    <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
    #   </hostscript>
    #   <times srtt="-1" rttvar="-1" to="1000000" />
    # </host>
    # <port protocol="tcp" portid="25">
    #  <state state="open" reason="syn-ack" reason_ttl="0"/>
    #   <service name="smtp" product="Exim smtpd" version="4.76" hostname="grostruc" method="probed" conf="10">
    #     <cpe>cpe:/a:exim:exim:4.76</cpe>
    #   </service>
    #   <script id="smtp-commands" output="grostruc Hello localhost [127.0.0.1], SIZE 52428800, PIPELINING, HELP, &#xa; Commands supported: AUTH HELO EHLO MAIL RCPT DATA NOOP QUIT RSET HELP "/>
    # </port>
    scan_result = {}
    try:
        dom = ElementTree.fromstring(output)
    except Exception:
        if len(error) > 0:
            raise lib.errors.NmapScannerError(error)
        else:
            raise lib.errors.NmapScannerError(output)
    # nmap command line
    scan_result['nmap'] = {
        'command_line': dom.get('args'),
        'scaninfo': {},
        'scanstats': {
            'timestr': dom.find("runstats/finished").get('timestr'),
            'elapsed': dom.find("runstats/finished").get('elapsed'),
            'uphosts': dom.find("runstats/hosts").get('up'),
            'downhosts': dom.find("runstats/hosts").get('down'),
            'totalhosts': dom.find("runstats/hosts").get('total')}
        }
    # if there was an error
    if len(error) > 0:
        scan_result['nmap']['scaninfo']['error'] = error
    # if there was a warning
    if len(warnings) > 0:
        scan_result['nmap']['scaninfo']['warning'] = warnings
    # info about scan
    for dsci in dom.findall('scaninfo'):
        scan_result['nmap']['scaninfo'][dsci.get('protocol')] = {
            'method': dsci.get('type'),
            'services': dsci.get('services')
            }
    scan_result['scan'] = {}
    for dhost in dom.findall('host'):
        # host ip, mac and other addresses
        host = None
        address_block = {}
        vendor_block = {}
        for address in dhost.findall('address'):
            addtype = address.get('addrtype')
            address_block[addtype] = address.get('addr')
            if addtype == 'ipv4':
                host = address_block[addtype]
            elif addtype == 'mac' and address.get('vendor') is not None:
                vendor_block[address_block[addtype]] = address.get('vendor')
        if host is None:
            host = dhost.find('address').get('addr')
        hostnames = []
        if len(dhost.findall('hostnames/hostname')) > 0:
            for dhostname in dhost.findall('hostnames/hostname'):
                hostnames.append({
                    'name': dhostname.get('name'),
                    'type': dhostname.get('type'),
                })
        else:
            hostnames.append({
                'name': '',
                'type': '',
            })
        scan_result['scan'][host] = {'hostnames': hostnames}
        scan_result['scan'][host]['addresses'] = address_block
        scan_result['scan'][host]['vendor'] = vendor_block
        for dstatus in dhost.findall('status'):
            # status : up...
            scan_result['scan'][host]['status'] = {'state': dstatus.get('state'),
                                                   'reason': dstatus.get('reason')}
        for dstatus in dhost.findall('uptime'):
            # uptime : seconds, lastboot
            scan_result['scan'][host]['uptime'] = {'seconds': dstatus.get('seconds'),
                                            'lastboot': dstatus.get('lastboot')}
        for dport in dhost.findall('ports/port'):
            # protocol
            proto = dport.get('protocol')
            # port number converted as integer
            port = int(dport.get('portid'))
            # state of the port
            state = dport.find('state').get('state')
            # reason
            reason = dport.find('state').get('reason')
            # name, product, version, extra info and conf if any
            name = product = version = extrainfo = conf = cpe = ''
            for dname in dport.findall('service'):
                name = dname.get('name')
                if dname.get('product'):
                    product = dname.get('product')
                if dname.get('version'):
                    version = dname.get('version')
                if dname.get('extrainfo'):
                    extrainfo = dname.get('extrainfo')
                if dname.get('conf'):
                    conf = dname.get('conf')
                for dcpe in dname.findall('cpe'):
                    cpe = dcpe.text
            # store everything
            if proto not in list(scan_result['scan'][host].keys()):
                scan_result['scan'][host][proto] = list()
            # Komand - change proto from dict to list to ease output spec
            scan_result['scan'][host][proto].append({
                'port': port,
                'state': state,
                'reason': reason,
                'name': name,
                'product': product,
                'version': version,
                'extrainfo': extrainfo,
                'conf': conf,
                'cpe': cpe
            })
            script_id = ''
            script_out = ''
            # get script output if any
            for dscript in dport.findall('script'):
                script_id = dscript.get('id')
                script_out = dscript.get('output')
                if 'script' not in list(scan_result['scan'][host][proto][port].keys()):
                    scan_result['scan'][host][proto][port]['script'] = {}
                scan_result['scan'][host][proto][port]['script'][script_id] = script_out
        # <hostscript>
        #  <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
        #  <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
        #  <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
        # </hostscript>
        for dhostscript in dhost.findall('hostscript'):
            for dname in dhostscript.findall('script'):
                hsid = dname.get('id')
                hsoutput = dname.get('output')
                if 'hostscript' not in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host]['hostscript'] = []
                scan_result['scan'][host]['hostscript'].append(
                    {
                        'id': hsid,
                        'output': hsoutput
                        }
                    )
        # <osmatch name="Juniper SA4000 SSL VPN gateway (IVE OS 7.0)" accuracy="98" line="36241">
        # <osclass type="firewall" vendor="Juniper" osfamily="IVE OS" osgen="7.X"
        # accuracy="98"><cpe>cpe:/h:juniper:sa4000</cpe><cpe>cpe:/o:juniper:ive_os:7</cpe></osclass>
        # </osmatch>
        # <osmatch name="Cymphonix EX550 firewall" accuracy="98" line="17929">
        # <osclass type="firewall" vendor="Cymphonix" osfamily="embedded"
        # accuracy="98"><cpe>cpe:/h:cymphonix:ex550</cpe></osclass>
        # </osmatch>
        for dos in dhost.findall('os'):
            osmatch = []
            portused = []
            for dportused in dos.findall('portused'):
                # <portused state="open" proto="tcp" portid="443"/>
                state = dportused.get('state')
                proto = dportused.get('proto')
                portid = dportused.get('portid')
                portused.append({
                    'state': state,
                    'proto': proto,
                    'portid': portid,
                })
            scan_result['scan'][host]['portused'] = portused
            for dosmatch in dos.findall('osmatch'):
                # <osmatch name="Linux 3.7 - 3.15" accuracy="100" line="52790">
                name = dosmatch.get('name')
                accuracy = dosmatch.get('accuracy')
                line = dosmatch.get('line')
                osclass = []
                for dosclass in dosmatch.findall('osclass'):
                    # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                    ostype = dosclass.get('type')
                    vendor = dosclass.get('vendor')
                    osfamily = dosclass.get('osfamily')
                    osgen = dosclass.get('osgen')
                    accuracy = dosclass.get('accuracy')
                    cpe = []
                    for dcpe in dosclass.findall('cpe'):
                        cpe.append(dcpe.text)
                    osclass.append({
                        'type': ostype,
                        'vendor': vendor,
                        'osfamily': osfamily,
                        'osgen': osgen,
                        'accuracy': accuracy,
                        'cpe': cpe,
                    })
                osmatch.append({
                    'name': name,
                    'accuracy': accuracy,
                    'line': line,
                    'osclass': osclass
                })
            else:
                scan_result['scan'][host]['osmatch'] = osmatch
        for dport in dhost.findall('osfingerprint'):
            # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
            fingerprint = dport.get('fingerprint')
            scan_result['scan'][host]['fingerprint'] = fingerprint
    return scan_result