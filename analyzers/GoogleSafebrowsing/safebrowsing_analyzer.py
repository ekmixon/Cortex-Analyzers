#!/usr/bin/env python3

import safebrowsing
from cortexutils.analyzer import Analyzer


class SafebrowsingAnalyzer(Analyzer):
    """Cortex analyzer to query Google Safebrowsing for URLs. Info how to obtain an API key can be found
    `here <https://developers.google.com/safe-browsing/v4/get-started>`_."""
    def __init__(self):
        Analyzer.__init__(self)
        self.api_key = self.get_param('config.key', None, 'No Google API key provided.')
        self.client_id = self.get_param('config.client_id', 'Cortex')
        self.client_version = '0.1'

        self.sb = safebrowsing.SafebrowsingClient(
            key=self.api_key,
            client_id=self.client_id,
            client_version=self.client_version
        )

    def summary(self, raw):
        level = "info"
        namespace = "Google"
        predicate = "Safebrowsing"
        value = "0 match"

        if "results" in raw:
            r = len(raw['results'])

            value = f"{r} match" if r in {0, 1} else f"{r} matches"
            level = "malicious" if r > 0 else "safe"
                # level : info, safe, suspicious, malicious

        taxonomies = [self.build_taxonomy(level, namespace, predicate, value)]
        return {"taxonomies": taxonomies}

    def run(self):
        result = self.sb.query_url(self.get_data())
        report = [
            {
                'platform': match.get('platformType'),
                'threat': match.get('threatType'),
            }
            for match in result.get('matches', [])
        ]

        self.report({'results': report})


if __name__ == '__main__':
    SafebrowsingAnalyzer().run()
