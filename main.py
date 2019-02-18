import requests
import json
import os
from datetime import datetime


#
# class Demisto:
#
#     def __init__(self):
#         self.username = ""
#         self.password = ""
#         self.hostname = ''
#         self.lastRun = {}
#
#     def params(self):
#         return {'username': self.username, 'password': self.password, 'hostname': self.hostname,
#                 'proxy': {'http': 'http://172.16.1.1:8080', 'https': 'http://172.16.1.1:8080'}, 'organisationalId': '3'}
#
#     def command(self):
#         # return 'test-module'
#         return 'blueliv-get-enriched-alert'
#
#     def results(self, message):
#         print('Demisto: Result=' + json.dumps(message))
#
#     def getLastRun(self):
#         return self.lastRun
#
#     def setLastRun(self, lastRun):
#         self.lastRun = lastRun
#
#     def incidents(self, incidents):
#         print(incidents)
#
#     def args(self):
#         return {'id': 215}
#
#
# demisto = Demisto()


# PROXY = demisto.params().get('proxy')
# if not demisto.params().get('proxy', False):
#     del os.environ['HTTP_PROXY']
#     del os.environ['HTTPS_PROXY']
#     del os.environ['http_proxy']
#     del os.environ['https_proxy']


class Blueliv:
    def __init__(self):
        self.lastRun_id = 0
        self.credentials = \
            {
                'username': demisto.params().get('username'),
                'password': demisto.params().get('password')
            }
        self.hostname = demisto.params().get('hostname')

        self.orgid = demisto.params().get('organisationalId')

        self.session = requests.session()

        self.proxy = demisto.params().get('proxy')

        self.token = self.auth()

    def test_connection(self):
        # This is the call made when pressing the integration test button.
        if len(blueliv.token) == 63:
            return 'ok'
        else:
            return 'Failed'

    def auth(self):
        header = {'Content-Type': 'application/json'}
        response = self.session.post(self.hostname + "/api/v2/auth", headers=header,
                                     json=self.credentials, proxies=self.proxy)
        if response.status_code != 200:
            print('Login failed ' + response.status_code)
            return False
        json_response = json.loads(response.text)
        return json_response['token']

    def get_alert(self, id):
        return self.get_uri(
            self.hostname + '/api/v2/organization/' + self.orgid + '/module/18/credential/alerts/' + str(
                id) + '?page=1&maxRows=10')

    def get_modules(self):
        return self.get_uri(self.hostname + '/api/v2/organization/' + self.orgid + '/module')

    def get_credentials(self, resource_id):
        return self.get_uri(
            self.hostname + '/api/v2/organization/' + self.orgid + '/module/22/credential/resource/' + str(resource_id))

    def get_uri(self, uri):
        header = {'x-cookie': self.token, 'Accept': 'application/json'}
        response = self.session.get(uri,
                                    headers=header, proxies=self.proxy)
        if response.status_code != 200:
            # print('Alert receive failed ' + str(response.status_code))
            return response.status_code
        return json.loads(response.text)

    def get_enriched_alert(self, id):
        alert = blueliv.get_alert(id)
        if alert == 404:
            return False
        else:
            return self.build_incident(alert)

    def build_incident(self, alert):
        for module in self.get_modules():
            if module['id'] == alert['moduleId']:
                alert['module'] = module
                break

        for resource in alert['resources']:
            credentials = blueliv.get_credentials(resource['id'])

            mod_alert = alert
            if 'resource' in mod_alert:
                del mod_alert['resource']
            else:
                del mod_alert['resources']
            mod_alert['credentials'] = credentials['credentials']
            mod_alert['resource'] = resource

            timestamp = int(mod_alert['createdAt']) / 1000
            createdAtTimestamp = datetime.utcfromtimestamp(timestamp)

            wrapper = {
                "eventId": mod_alert["id"],
                "name": mod_alert['module']['name'] + " #" + str(mod_alert["id"]),
                "rawResponse": mod_alert, "credentials": mod_alert['credentials'],
                'occurred': createdAtTimestamp.isoformat()
            }

            return {"Name": mod_alert['module']['name'] + " #" + str(mod_alert["id"]),
                    "rawJSON": json.dumps(wrapper)}

    def fetch_new_incidents(self):
        lastAlert = 0
        incidents = []
        try:
            lastRun = demisto.getLastRun()
            lastAlert = lastRun['alert']
        except KeyError:
            lastAlert = 221

        while True:
            alert = blueliv.get_alert(lastAlert + 1)
            if alert == 404:
                break
            else:
                lastAlert = lastAlert + 1
                demisto.setLastRun({'alert': lastAlert})

                incident = blueliv.build_incident(alert)

                incidents.append(incident)

        return incidents


blueliv = Blueliv()

try:
    if demisto.command() == 'test-module' or demisto.command() == 'blueliv-test-api-connection':
        # Tests connectivity and credentails on login
        demisto.results(blueliv.test_connection())
    elif demisto.command() == 'fetch-incidents':
        demisto.incidents(blueliv.fetch_new_incidents())
    elif demisto.command() == 'blueliv-get-alert':
        demisto.results(blueliv.get_alert(demisto.args()['id']))
    elif demisto.command() == 'blueliv-get-enriched-alert':
        demisto.results(blueliv.get_enriched_alert(demisto.args()['id']))
    elif demisto.command() == 'blueliv-get-modules':
        demisto.results(blueliv.get_modules())
    elif demisto.command() == 'blueliv-get-credentials-by-id':
        demisto.results(blueliv.get_credentials(demisto.args()['id']))
except Exception as e:
    print(e.message)
