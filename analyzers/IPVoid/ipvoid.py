#!/usr/bin/env python3

import requests

from cortexutils.analyzer import Analyzer

class IPVoid(Analyzer):
    """
    IPVoid API docs - https://app.apivoid.com/dashboard/api/ip-reputation/documentation/
    """

    def run(self):
        try:
            if self.data_type == 'ip':
                api_key = self.get_param('config.key',None, 'Missing API key')
                ip = self.get_data()

                url = f'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={api_key}&ip={ip}'

                response = requests.get(url)

                if not (200 <= response.status_code < 300):
                    self.error(f'Unable to query IPVoid API\n{response.text}')

                json_response = response.json()

                self.report(json_response)

            else:
                self.notSupported()
        except Exception as e:
            self.unexpectedError(e)


    def summary(self, raw):
        try:
            taxonomies = []

            #Parse the information section of the report into a Location taxonomy. Only a subset of keys included for now

            info = raw['data']['report']['information']

            location = info['city_name']+'/'+info['country_name']
            taxonomies += [self.build_taxonomy('info','IPVoid','Location',location)]

            #Parse blacklists info 
            detections = raw['data']['report']['blacklists']['detections']
            engines = raw['data']['report']['blacklists']['engines_count']

            if detections > 0:
                taxonomies += [
                    self.build_taxonomy(
                        'suspicious',
                        'IPVoid',
                        'Blacklists',
                        f"{str(detections)}/{str(engines)}",
                    )
                ]

            else:
                taxonomies += [
                    self.build_taxonomy(
                        'info',
                        'IPVoid',
                        'Blacklists',
                        f"{str(detections)}/{str(engines)}",
                    )
                ]


            return({'taxonomies':taxonomies})

        except Exception as e:
            if 'error' in raw:
                self.unexpectedError(raw['error'])
            else:
                self.unexpectedError(e)

if __name__ == '__main__':
    IPVoid().run()

