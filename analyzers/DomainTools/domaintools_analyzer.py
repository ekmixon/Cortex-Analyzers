#!/usr/bin/env python3
# encoding: utf-8

from domaintools.exceptions import NotFoundException
from domaintools.exceptions import NotAuthorizedException
from domaintools.exceptions import ServiceUnavailableException


from domaintools import API


from cortexutils.analyzer import Analyzer


class DomainToolsAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            'config.service', None, 'Service parameter is missing')

    def domaintools(self, data):
        """

        :param service:
        :return:
        """
        if (self.service == 'reverse-ip' and self.data_type == 'ip'):
            self.service = 'host-domains'

        api = API(self.get_param('config.username'), self.get_param('config.key'))

        if self.service == 'reverse-ip' and self.data_type in ['domain', 'ip', 'fqdn']:
            response = api.reverse_ip(data).response()

        elif self.service == 'host-domains' and self.data_type == 'ip':
            response = api.host_domains(data).response()

        elif self.service == 'name-server-domains' and self.data_type == 'domain':
            response = api.reverse_name_server(data).response()

        elif self.service == 'whois/history' and self.data_type == 'domain':
            response = api.whois_history(data).response()

        elif self.service == 'whois/parsed' and self.data_type in ['domain','ip']:
            response = api.parsed_whois(data).response()

        elif self.service == 'hosting-history' and self.data_type == 'domain':
            response = api.hosting_history(data).response()
        
        elif self.service == 'risk_evidence' and self.data_type in ['domain', 'fqdn']:
            response = api.risk_evidence(data).response()

        elif self.service == 'reputation' and self.data_type in ['domain', 'fqdn']:
            response = api.reputation(data, include_reasons=True).response()

        elif self.service == 'reverse-whois':
            scope = self.getParam('parameters.scope', 'current', None)
            response = api.reverse_whois(data, mode='purchase', scope=scope).response()

        elif self.service == 'reverse-ip-whois':
            response = api.reverse_ip_whois(data).response()

        elif self.service == 'whois' and self.data_type in ['domain', 'ip']:
            response = api.whois(data).response()

        return response


    def summary(self, raw):

        r = {
            "service": self.service,
            "dataType": self.data_type
        }

        if "ip_addresses" in raw:
            if type(raw["ip_addresses"]) == dict:
                r["ip"] = {
                    "address": raw["ip_addresses"]["ip_address"],
                    "domain_count": raw["ip_addresses"]["domain_count"]
                }
            elif type(raw["ip_addresses"]) == list:
                r["ip"] = {
                    "address": f"{len(r)} IP addresses",
                    "domain_count": sum(
                        d["domain_count"] for d in raw["ip_addresses"]
                    ),
                }


        if "record_count" in raw:
            r["record_count"] = raw.get('record_count')

        if "domain_count" in raw:
            r["domain_count"] = {
                "current": raw["domain_count"]["current"],
                "historic": raw["domain_count"]["historic"]
            }

        if "registrar_history" in raw:
            r["registrar_history"] = len(raw["registrar_history"])
        if "ip_history" in raw:
            r["ip_history"] = len(raw["ip_history"])
        if "nameserver_history" in raw:
            r["ns_history"] = len(raw["nameserver_history"])

        if "record_count" in raw:
            r["record_count"] = raw["record_count"]

        if "registrant" in raw:
            r["registrant"] = raw["registrant"]
        elif "response" in raw and "registrant" in raw["response"]:
            r["registrant"] = raw["response"]["registrant"]

        if "parsed_whois" in raw:
            r["registrar"] = raw["parsed_whois"]["registrar"]["name"]

        if "name_server" in raw:
            r["name_server"] = raw["name_server"]["hostname"]
            r["domain_count"] = raw["name_server"]["total"]

        if "risk_score" in raw:
            r["risk_score"] = raw["risk_score"]
            if "reasons" in raw:
                r["reputation"] = True

        taxonomies = []

        # Prepare predicate and value for each service
        if r["service"] in ["reverse-ip", "host-domains"]:
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    "DT",
                    "Reverse_IP",
                    f'{r["ip"]["address"]}, {r["ip"]["domain_count"]} domains',
                )
            )


        if r["service"] == "name-server-domains":
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    "DT",
                    "Reverse_Name_Server",
                    f'{r["name_server"]}, {r["domain_count"]} domains',
                )
            )


        if r["service"] == "reverse-whois":
            taxonomies.append(self.build_taxonomy("info", "DT", "Reverse_Whois",
                                                  "curr:{} / hist:{} domains".format(r["domain_count"]["current"],
                                                                                         r["domain_count"][
                                                                                             "historic"])))

        if r["service"] == "reverse-ip-whois":
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    "DT",
                    "Reverse_IP_Whois",
                    f'records:{r["record_count"]}',
                )
            )


        if r["service"] == "hosting-history":
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    "DT",
                    "Hosting_History",
                    f'registrars:{r["registrar_history"]} / ips:{r["ip_history"]} / ns:{r["ns_history"]}',
                )
            )


        if r["service"] == "whois/history":
            taxonomies.append(
                self.build_taxonomy(
                    "info",
                    "DT",
                    "Whois_History",
                    f'{r["record_count"]} {"records" if r["record_count"] > 1 else "record"}',
                )
            )


        if r["service"] == "whois/parsed" or r['service'] == "whois":
            if r["registrar"]:
                taxonomies.append(
                    self.build_taxonomy(
                        "info", "DT", "Whois", f'REGISTRAR:{r["registrar"]}'
                    )
                )

            if r["registrant"]:
                taxonomies.append(
                    self.build_taxonomy(
                        "info", "DT", "Whois", f'REGISTRANT:{r["registrant"]}'
                    )
                )



        if "risk_score" in r:
            risk_service = "Reputation" if "reputation" in r else "Risk"
            if r["risk_score"] == 0:
                level = "safe"
            elif 0 < r["risk_score"] <= 50:
                level = "suspicious"
            elif r["risk_score"] > 50:
                level = "malicious"
            taxonomies.append(
                self.build_taxonomy(
                    level, "DT", risk_service, f'{r["risk_score"]}'
                )
            )


        return {'taxonomies': taxonomies}

    def run(self):
        data = self.get_data()

        try:
            r = self.domaintools(data)

            if 'response' in r:
                self.report(r.get('response'))
            elif 'error' in r and 'message' in r['error']:
                self.error(r['error']['message'])
            else:
                self.report(r)

        except NotFoundException:
            self.error(f"{self.data_type.capitalize()} not found")
        except NotAuthorizedException:
            self.error("An authorization error occurred")
        except ServiceUnavailableException:
            self.error("DomainTools Service is currenlty unavailable")
        except Exception as e:
            self.unexpectedError(e)


if __name__ == '__main__':
    DomainToolsAnalyzer().run()
