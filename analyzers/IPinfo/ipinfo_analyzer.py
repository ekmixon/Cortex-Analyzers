#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.analyzer import Analyzer
from ipinfo import IPinfoException, IPinfo


class IPinfoAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "IPinfo service is missing")

        self.api_key = self.get_param(
            "config.api_key", None, "IPinfo API key is missing")

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "IPinfo"

        if self.service == "details":
            if country := raw.get("country"):
                taxonomies.append(
                    self.build_taxonomy(level, namespace, "Country", country)
                )

            asn = raw.get("asn")
            if asn and asn.get("asn"):
                taxonomies.append(
                    self.build_taxonomy(
                        level, namespace, "ASN", asn.get("asn"))
                )

        elif self.service == "hosted_domains":
            total = len(raw["domains"]) if "domains" in raw else 0
            value = f"{total} record" if total < 2 else f"{total} records"
            taxonomies.append(
                self.build_taxonomy(level, namespace, "HostedDomains", value)
            )

        return {"taxonomies": taxonomies}

    def run(self):
        data = self.get_data()

        try:
            ipinfo = IPinfo(api_key=self.api_key)

            if self.service == "details":
                result = ipinfo.details(data)
                self.report(result)
            elif self.service == "hosted_domains":
                result = ipinfo.hosted_domains(data)
                self.report(result)
            else:
                self.error("Unknown IPinfo service")

        except IPinfoException as e:
            self.error(str(e))


if __name__ == "__main__":
    IPinfoAnalyzer().run()
