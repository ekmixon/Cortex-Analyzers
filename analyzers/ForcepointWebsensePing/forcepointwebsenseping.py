#!/usr/bin/env python3
# encoding: utf-8


import subprocess
from cortexutils.analyzer import Analyzer


class WebsensePingAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.hostname = self.get_param('config.hostname', None)
        self.timeout = self.get_param('config.timeout', None)
        self.path = self.get_param('config.path', None)

def summary(self, raw):
    taxonomies = []
    if raw.get('Categories', None):
        value = raw['Categories']
        if value in self.get_param('config.malicious_categories', []):
            level = "malicious"
        elif value in self.get_param('config.suspicious_categories', []):
            level = "suspicious"
        elif value in self.get_param('config.safe_categories', []):
            level = "safe"
        else:
            level = "info"
        taxonomies.append(self.build_taxonomy(level, "Forcepoint", "WebsensePing", value))
    return {"taxonomies": taxonomies}


if __name__ == '__main__':
    WebsensePingAnalyzer().run()
