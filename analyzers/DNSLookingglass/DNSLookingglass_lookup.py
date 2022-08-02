#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
import iocextract
from cortexutils.analyzer import Analyzer

class DNSLookingglassAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def lookingglass_checkdomain(self, data):
        url = f'https://isc.sans.edu/api/dnslookup/{data}?json'
        r = requests.get(url)

        return json.loads(r.text)

    def artifacts(self, raw):
        artifacts = []
        ipv4s = list(iocextract.extract_ipv4s(str(raw)))
        ipv6s = list(iocextract.extract_ipv6s(str(raw)))

        if ipv4s:
            ipv4s = list(dict.fromkeys(ipv4s))
            artifacts.extend(self.build_artifact('ip',str(i)) for i in ipv4s)
        if ipv6s:
            ipv6s = list(dict.fromkeys(ipv6s))
            artifacts.extend(self.build_artifact('ip',str(j)) for j in ipv6s)
        return artifacts

    def summary(self, raw):
        level = "info"
        namespace = "Lookingglass"
        predicate = "ERR"
        value = "-"

        value = f"{raw['count']} hit(s)"
        predicate = raw['hits']

        taxonomies = [self.build_taxonomy(level, namespace, predicate, value)]
        return {"taxonomies": taxonomies}

    def get_hits(self, hits):
        if hits == 0:
            return("NXDOMAIN")
        elif hits >= 1:
            return("DomainExist")
        else:
            return("Error")

    def run(self):
        if self.data_type in ['domain', 'fqdn']:
            data = self.get_param('data', None, 'Domain is missing')
            r = self.lookingglass_checkdomain(data)

            if len(r) != 0:
                results = {'results': []}
                for hit in r:
                    result = {}
                    try:
                        result['answer'] = hit['answer']
                        result['status'] = hit['status']
                        result['country'] = hit['country']
                        results['results'].append(result)
                    except KeyError:
                        pass

                results['hits'] = self.get_hits(len(results['results']))
                results['count'] = len(results['results'])

                self.report(results)
            else:
                self.error('No domain found')
        else:
            self.error('Invalid data type')

if __name__ == '__main__':
    DNSLookingglassAnalyzer().run()
