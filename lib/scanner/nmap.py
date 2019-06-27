import io
import os
import re
import csv
import sys
import shlex
import subprocess

from xml.etree import ElementTree
from multiprocessing import Process

import lib.jsonize
import lib.errors
import lib.output
import lib.settings


def write_xml_data(host, output):
    if not os.path.exists(lib.settings.NMAP_XML_OUTPUT_BACKUP):
        os.makedirs(lib.settings.NMAP_XML_OUTPUT_BACKUP)
    file_path = "{}/{}_{}.xml".format(
        lib.settings.NMAP_XML_OUTPUT_BACKUP, str(host), lib.jsonize.random_file_name(length=10)
    )
    with open(file_path, 'a+') as results:
        results.write(output)
    return file_path


def find_nmap(search_paths):
    for path in search_paths:
        try:
            _ = subprocess.Popen([path, '-V'], bufsize=10000, stdout=subprocess.PIPE, close_fds=True)
        except OSError:
            pass
        else:
            return path
    raise lib.errors.NmapNotFoundException


def do_scan(host, nmap_path, ports=None, arguments=None):
    if arguments is None:
        arguments = "-sV"
    arguments_list = shlex.split(arguments)
    launch_arguments = [
        nmap_path, '-oX', '-', host,
        '-p ' + ports if ports is not None else "",
    ] + arguments_list
    lib.output.info("launching nmap scan against {} ({})".format(host, " ".join(launch_arguments)))
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
    path = write_xml_data(host, output_data)
    lib.output.misc_info("a copy of the output has been saved to: {}".format(path))
    return output_data, "".join(nmap_warn_tracestack), "".join(nmap_error_tracestack)


def parse_xml_output(output, warnings, error):
    results = {}
    try:
        root = ElementTree.fromstring(output)
    except Exception:
        if len(error) != 0:
            raise lib.errors.NmapScannerError(error)
        else:
            raise lib.errors.NmapScannerError(output)
    results['nmap_scan'] = {
        'full_command_line': root.get('args'),
        'scan_information': {},
        'scan_stats': {
            'time_string': root.find('runstats/finished').get('timestr'),
            'elapsed': root.find('runstats/finished').get('elapsed'),
            'hosts_up': root.find('runstats/hosts').get('up'),
            'down_hosts': root.find('runstats/hosts').get('down'),
            'total_hosts_scanned': root.find('runstats/hosts').get('total')
        }
    }
    if len(error) != 0:
        results['nmap_scan']['scan_information']['errors'] = error
    if len(warnings) != 0:
        results['nmap_scan']['scan_information']['warnings'] = warnings
    for info in root.findall('scaninfo'):
        results['nmap_scan']['scan_information'][info.get('protocol')] = {
            'method': info.get('type'),
            'services': info.get('services')
        }
    for attempted_host in root.findall('host'):
        host = None
        addresses = {}
        vendors = {}
        for address in attempted_host.findall("address"):
            address_type = address.get('addrtype')
            addresses[address_type] = address.get('addr')
            if address_type == "ipv4":
                host = addresses[address_type]
            elif address_type == "mac" and address.get('vendor') is not None:
                vendors[addresses[address_type]] = address.get('vendor')
        if host is None:
            host = attempted_host.find('address').get('addr')
        hostnames = []
        if len(attempted_host.findall('hostnames/hostname')) != 0:
            for current_hostnames in attempted_host.findall('hostnames/hostname'):
                hostnames.append({
                    'hostname': current_hostnames.get('name'),
                    'host_type': current_hostnames.get('type')
                })
        else:
            hostnames.append({
                'hostname': None,
                'host_type': None
            })

        results['nmap_scan'][host] = {}
        results['nmap_scan'][host]['hostnames'] = hostnames
        results['nmap_scan'][host]['addresses'] = addresses
        results['nmap_scan'][host]['vendors'] = vendors

        print results;exit(1)

        for status in attempted_host.findall('status'):
            results['nmap_scan'][attempted_host]['status'] = {
                    'state': status.get('state'),
                    'reason': status.get('reason')
            }
        for uptime in attempted_host.findall('uptime'):
            results['nmap_scan'][attempted_host]['uptime'] = {
                    'seconds': uptime.get('seconds'),
                    'lastboot': uptime.get('lastboot')
            }
        for discovered_port in attempted_host.findall('ports/port'):
            protocol = discovered_port.get('protocol')
            port_number = discovered_port.get('portid')
            port_state = discovered_port.find('state').get('reason')

            # damn I didn't even know you could do this!
            for discovered_name in discovered_port.findall('service'):
                name = discovered_name.get('name')
                if discovered_name.get('product'):
                    discovered_product = discovered_name.get('product')
                if discovered_name.get('version'):
                    discovered_version = discovered_name.get('version')
                if discovered_name.get('extrainfo'):
                    extra_information = discovered_name.get('extrainfo')
    print results