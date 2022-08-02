#!/usr/bin/env python3
# encoding: utf-8
import requests
from cortexutils.analyzer import Analyzer


class HashddAnalyzer(Analyzer):
    service = "Status"
    url = "https://api.hashdd.com/"
    hashdd_key = None

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )

        if self.service == "status":
            self.hashdd_key = self.get_param("config.api_key", None)
            self.url = "https://api.hashdd.com/v1/knownlevel/"
        elif self.service == "detail":
            self.hashdd_key = self.get_param(
                "config.api_key", None, "Missing hashdd API key"
            )
            self.url = "https://api.hashdd.com/v1/detail/"

    def hashdd_check(self, data):
        headers = {} if self.hashdd_key is None else {"X-API-KEY": self.hashdd_key}
        r = requests.get(f"{self.url}{data}", headers=headers, verify=False)
        r.raise_for_status()  # Raise exception on HTTP errors
        return r.json()

    def summary(self, raw):
        namespace = "Hashdd"
        predicate = "knownlevel"
        value = "Unknown"
        knownlevel = "Unknown"
        level = "info"
        if self.service == "status" and "knownlevel" in raw:
            knownlevel = raw["knownlevel"]
            if knownlevel == "Bad":
                level = "malicious"
            elif knownlevel == "Good":
                level = "safe"
            value = f"{knownlevel}"

        elif self.service == "detail":
            if "Bad" in [x["knownlevel"] for x in raw["search_results"]]:
                level = "malicious"
                knownlevel = "Bad"
            elif "Good" in [x["knownlevel"] for x in raw["search_results"]]:
                level = "safe"
                knownlevel = "Good"
            value = f"{knownlevel}"
        taxonomies = [self.build_taxonomy(level, namespace, predicate, value)]
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type != "hash":
            self.notSupported()

        data = self.get_param("data", None, "Data is missing")
        response = self.hashdd_check(data)

        if response["result"] == "SUCCESS":
            if self.service == "status":
                self.report({"knownlevel": response["knownlevel"]})
            elif self.service == "detail":
                self.report(response)
        else:
            self.error(f'{response["result"]}')


if __name__ == "__main__":
    HashddAnalyzer().run()
