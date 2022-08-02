#!/usr/bin/env python3
# encoding: utf-8
import json
import requests

from cortexutils.analyzer import Analyzer


class C1fQueryAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.cif_key = self.get_param('config.key', None, 'Missing C1fApp API key')
        self.api_url = self.get_param('config.url', None, 'Missing API URL')

    @staticmethod
    def _getheaders():
        return {
            'user-agent': "cortex-analyzer-v1.0",
            'Accept': 'application/json'
        }

    @staticmethod
    def cleanup(return_data):

        assessments = []
        feed_labels = []
        descriptions = []
        asns = []
        asn_descs = []
        countries = []
        domains = []
        ip_addresses = []

        found = False
        count = 0

        for entry in return_data:
            found = True
            assessments.append(entry.get('assessment'))
            feed_labels.append(entry.get('feed_label'))
            descriptions.append(entry.get('description'))
            asns.append(entry.get('asn'))
            asn_descs.append(entry.get('asn_desc'))
            countries.append(entry.get('country'))
            domains.extend((entry.get('domain'), entry.get('fqdn')))
            dga_indication = entry.get('dga')

            if list(entry.get('ip_address')):
                ip_addresses.extend(iter(entry.get('ip_address')))
            else:
                ip_addresses.append(entry.get('ip_address'))

        return {
            'assessment': list(set(assessments[0])),
            'feed_label': list(set(feed_labels[0])),
            'description': list(set(descriptions[0])),
            'asn': list(set(asns[0])),
            'asn_desc': list(set(asn_descs[0])),
            'country': list(set(countries[0])),
            'domains': list(set(domains[0])),
            'ip_addresses': list(set(ip_addresses)),
            'dga': dga_indication,
            'found': found,
            'count': len(return_data),
        }

    def c1f_query(self, data):
        headers = self._getheaders()
        try:
            _session = requests.Session()

            payload = {'key': self.cif_key,
                       'format': 'json',
                       'backend': 'es',
                       'request': data
                       }

            _query = _session.post(self.api_url, headers=headers,
                                   data=json.dumps(payload))
            if _query.status_code == 200:
                return {} if _query.text == "[]" else self.cleanup(_query.json())
            else:
                self.error(f'API Access error: {_query.text}')

        except Exception as e:
            self.error('API Request error')

        return {}

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "C1fApp"
        predicate = "Assessment"
        for a in raw["assessment"]:
            if a in ["whitelist"]:
                level = "safe"
            elif a in ["suspicious"]:
                level = "suspicious"
            elif a in ["phishing", "malware", "botnet", "Exploit"]:
                level = "malicious"
            value = f"{a}"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type in ['url', 'domain', 'ip']:
            data = self.get_param('data', None, 'Data is missing')

            rep = self.c1f_query(data)
            self.report(rep)

        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    C1fQueryAnalyzer().run()
