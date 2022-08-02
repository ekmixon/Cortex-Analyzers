#!/usr/bin/env python3

import ipaddress
import os
import re
from io import open
from time import sleep
import datetime as dt
import pytz
from dateutil.parser import parse

from cortexutils.analyzer import Analyzer


class FireholBlocklistsAnalyzer(Analyzer):
    """Analyzer that compares ips from TheHive to FireHOL ip blocking lists. Check them out under
    `iplists.firehol.org <https://iplists.firehol.org/>`_"""

    def __init__(self):
        Analyzer.__init__(self)

        # Get config parameters
        self.path = self.get_param('config.blocklistpath', None, 'No path to blocklists provided.')
        self.ignoreolderthandays = self.get_param('config.ignoreolderthandays', 365)
        self.utc = pytz.UTC
        self.now = dt.datetime.now(tz=self.utc)

        # Check if directory exists
        if not os.path.exists(self.path):
            os.mkdir(self.path, 0o0700)
            # Downloading/updating the list is implemented with an external cronjob which git pulls the repo

        # Read files in the given path and prepare file lists for ip- and netsets
        files = os.listdir(self.path)
        self.ipsets = []
        self.netsets = []
        for file in files:
            if '.ipset' in file:
                self.ipsets.append(file)
            elif '.netset' in file:
                self.netsets.append(file)

    def _check_ip(self, ip):
        """Here all the workload happens. Read the files, check if the ip is in there and report the results.
        If the lock file is found, which gets created when lists are getting updated, the script starts to sleep 10
        seconds before checking again. Also reads the source file date and checks, if its too old (ignoreolderthandays
        parameter).

        :param ip: IP to search for.
        :type ip: str
        :returns: List of hits containing dictionaries.
        :rtype: list
        """

        # hits will be the variable to store all matches
        hits = []
        description = {}
        file_date = {}
        # Check for lock
        while os.path.isfile(f'{self.path}/.lock'):
            sleep(10)

        # First: check the ipsets
        for ipset in self.ipsets:
            with open(f'{self.path}/{ipset}') as afile:
                ipsetname = ipset.split('.')[0]
                description[ipsetname] = ''
                file_date[ipsetname] = ''
                for l in afile:
                    if l[0] == '#':
                        # Check for date and break if too old
                        if '# Source File Date: ' in l:
                            datestr = re.sub('# Source File Date: ', '', l.rstrip('\n'))
                            date = parse(datestr)
                            file_date[ipsetname] = str(date)
                            if (self.now - date).days > self.ignoreolderthandays:
                                break
                        description[ipsetname] += re.sub(r'^\[.*\] \(.*\) [a-zA-Z0-9.\- ]*$', '', l.lstrip('# '))\
                                .replace('\n\n', '\n')
                    elif ip in l:
                        # On match append to hits and break; next file!
                        hits.append({'list': ipsetname, 'description': description.get(ipsetname),
                                     'file_date': file_date.get(ipsetname)})
                        break

        # Second: check the netsets
        for netset in self.netsets:
            with open(f'{self.path}/{netset}') as afile:
                netsetname = netset.split('.')[0]
                description[netsetname] = ''
                file_date[netsetname] = ''
                for l in afile:
                    if l[0] == '#':
                        # Check for date and break if too old
                        if '# Source File Date: ' in l:
                            datestr = re.sub('# Source File Date: ', '', l.rstrip('\n'))
                            date = parse(datestr)
                            file_date[netsetname] = str(date)
                            if (self.now - date).days > self.ignoreolderthandays:
                                break
                        description[netsetname] += re.sub(r'^\[.*\] \(.*\) [a-zA-Z0-9.\- ]*$', '', l.lstrip('# '))\
                                .replace('\n\n', '\n')
                    else:
                        try:
                            if ipaddress.ip_address(ip) in ipaddress.ip_network(u'{}'.format(l.split('\n')[0])):
                                hits.append({'list': netsetname, 'description': description.get(netsetname),
                                             'file_date': file_date.get(netsetname)})
                                break
                        except ValueError as e:
                            self.error(
                                f'ValueError occurred. Used values: ipnetwork {l}, ip to check {ip}, file {netset}.Error message: {e}'
                            )


        return hits

    def summary(self, raw):
        taxonomies = []
        value = "0 hit"

        if 'count' in raw:
            r = raw.get('count', 0)

            value = f"{r} hit" if r in [0, 1] else f"{r} hits"
            level = "suspicious" if r > 0 else "safe"
            namespace = "Firehol"
            predicate = "Blocklists"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        ip = self.get_data()
        if '/' in ip:
            self.error('CIDR notation currently not supported.')
        hits = self._check_ip(ip)
        self.report({'hits': hits, 'count': len(hits)})


if __name__ == '__main__':
    FireholBlocklistsAnalyzer().run()
