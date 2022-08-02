#!/usr/bin/env python3
import pypdns
from cortexutils.analyzer import Analyzer


class CIRCLPassiveDNSAnalyzer(Analyzer):
    """The circl.lu passive dns is queried using the PyPDNS module from circl.lu."""
    def __init__(self):
        Analyzer.__init__(self)
        self.pdns = pypdns.PyPDNS(basic_auth=(self.get_param('config.user', None, 'No passiveDNS username given.'),
                                              self.get_param('config.password', None, 'No passiveDNS password given.')))

    def query(self, domain):
        """The actual query happens here. Time from queries is replaced with isoformat.

        :param domain: The domain which should gets queried.
        :type domain: str
        :returns: List of dicts containing the search results.
        :rtype: [list, dict]
        """
        result = {}

        try:
            result = self.pdns.query(domain)
        except:
            self.error('Exception while querying passiveDNS. Check the domain format.')

        # Clean the datetime problems in order to correct the json serializability
        clean_result = []
        for resultset in result:
            if resultset.get('time_first', None):
                resultset['time_first'] = resultset.get('time_first').isoformat(' ')
            if resultset.get('time_last', None):
                resultset['time_last'] = resultset.get('time_last').isoformat(' ')
            clean_result.append(resultset)

        return clean_result

    def summary(self, raw):
        level = "info"
        namespace = "CIRCL"
        predicate = "PassiveDNS"
        r = len(raw.get('results')) if "results" in raw else 0
        value = f"{r} record" if r in {0, 1} else f"{r} records"
        taxonomies = [self.build_taxonomy(level, namespace, predicate, value)]
        return {"taxonomies": taxonomies}

    def run(self):
        query = ''
        if self.data_type == 'url':
            splittedurl = self.get_data().split('/')
            query = splittedurl[2] if 'http' in splittedurl[0] else splittedurl[0]
        elif self.data_type == 'domain':
            query = self.get_data()
            if '/' in query:
                self.error('\'/\' found in the supplied domain. use the URL datatype instead')
        elif self.data_type == 'ip':
            query = self.getData()
        else:
            self.error('invalid datatype')
        self.report({'results': self.query(query)})


if __name__ == '__main__':
    CIRCLPassiveDNSAnalyzer().run()
