#!/usr/bin/env python3
import os
import io
import sys
import json
import yara
import requests
import datetime

from cortexutils.analyzer import Analyzer
from requests.auth import HTTPBasicAuth
from stat import ST_MTIME


class MalpediaAnalyzer(Analyzer):
    """Checking binaries through yara rules. This analyzer requires a list of yara rule paths in the cortex
    configuration. If a path is given, an index file is expected."""

    def __init__(self):
        Analyzer.__init__(self)

        self.baseurl = "https://malpedia.caad.fkie.fraunhofer.de/api/get"
        self.rulepaths = self.get_param('config.path', None, 'No rulepath provided.')
        self.user = self.get_param('config.username', None, 'No username provided.')
        self.pwd = self.get_param('config.password', None, 'No password provided.')
        self.update_hours = int(self.get_param('config.update_hours', 10))

        if not os.path.exists(self.rulepaths):
            os.makedirs(self.rulepaths)

        timestamps = []
        try:
            for fn in os.listdir(self.rulepaths):
                timestamps.extend(
                    datetime.datetime.fromtimestamp(os.stat(path)[ST_MTIME])
                    for path in os.path.join(self.rulepaths, fn)
                    if os.path.isfile(path) and path.endswith('.yar')
                )

            newest = max(timestamps)
            hours = (datetime.datetime.now() - newest).seconds / 3600
        except ValueError:
            hours = self.update_hours + 1

        if hours > self.update_hours or not timestamps:
            try:
                req = requests.get(
                    f'{self.baseurl}/yara/after/2010-01-01?format=json',
                    auth=HTTPBasicAuth(self.user, self.pwd),
                )

                if req.status_code == requests.codes.ok:
                    rules_json = json.loads(req.text)
                    for color, color_data in rules_json.items():
                        for rule_name, rule_text in color_data.items():
                            with io.open(os.path.join(self.rulepaths, rule_name), 'w', encoding='utf-8') as f:
                                f.write(rule_text)
                else:
                    self.error(
                        f'Could not download new rules due tue HTTP {req.status_code}: {req.text}'
                    )

            except Exception as e:
                with io.open(f'{os.path.join(self.rulepaths, "error.txt")}', 'w') as f:
                    f.write(f'Error: {e}\n')

    def check(self, file):
        """
        Checks a given file against all available yara rules
        :param file: Path to file
        :type file:str
        :returns: Python list with matched rules info
        :rtype: list
        """
        result = []
        all_matches = []
        for filerules in os.listdir(self.rulepaths):
            try:
                rule = yara.compile(os.path.join(self.rulepaths, filerules))
            except yara.SyntaxError:
                continue
            matches = rule.match(file)
            if len(matches) > 0:
                for rulem in matches:
                    rule_family = "_".join(list(rulem.rule.replace("_", ".", 1).split("_")[:-1]))
                    if rule_family not in all_matches:
                        all_matches.append(rule_family)
        for rule_family in all_matches:
            rules_info_txt = requests.get(
                f'{self.baseurl}/family/{rule_family}',
                auth=HTTPBasicAuth(self.user, self.pwd),
            )

            rules_info_json = json.loads(rules_info_txt.text)
            result.append({
                'family': rule_family,
                'common_name': rules_info_json['common_name'],
                'description': rules_info_json['description'],
                'attribution': rules_info_json['attribution'],
                'alt_names': rules_info_json['alt_names'],
                'urls': rules_info_json['urls']
            })

        return result

    def summary(self, raw):
        namespace = "Malpedia"
        predicate = "Match"

        value = f'{len(raw["results"])} rule(s)'
        level = "safe" if len(raw["results"]) == 0 else "malicious"
        taxonomies = [self.build_taxonomy(level, namespace, predicate, value)]
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'file':
            self.report({'results': self.check(self.get_param('file', None, 'No file given.'))})
        else:
            self.error('Wrong data type.')


if __name__ == '__main__':
    MalpediaAnalyzer().run()
