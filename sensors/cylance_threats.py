""" Cylance Protect ST2 Sensor """

from datetime import datetime, timedelta

from st2reactor.sensor.base import PollingSensor
from lib.cylance import CylanceProtectClient


class CylanceProtectSensor(PollingSensor):
    """ Cylance Sensor for Creating ST2 Triggers for Cylance Threats """
    def __init__(self, sensor_service, config=None, poll_interval=120):
        super(CylanceProtectSensor, self).__init__(sensor_service=sensor_service, config=config,
                                            poll_interval=poll_interval)

        self._logger = sensor_service.get_logger(__name__)

        self._trigger_ref = 'cylance_protect.threat'

        if config is None:
            raise ValueError("No connection config found")

        self._timestamps = {}
        self.tenants = []
        self.instances = {}
        self.params = {}

        credentials = config.get('cylance_protect')

        for tenant, creds in credentials.items():
            tenant_value = creds.get('tenant_value', None)
            app_id = creds.get('app _id', None)
            app_secret = creds.get('app_secret', None)

            self.instances[tenant] = CylanceProtectClient(tenant_value, app_id, app_secret)
            self.tenants.append(tenant)

    def setup(self):
        pass

    def poll(self):

        for tenant in self.tenants:
            last_timestamp = self._get_last_timestamp(tenant)

            page_number = 1
            page_size = 20
            more_threats = True

            self._logger.info('Checking for threats since {} for tenant {}'.format(last_timestamp,
                                                                                  tenant))
            client_instance = self.instances[tenant]

            while more_threats:
                threats = client_instance.get_threats(page=page_number, page_size=page_size)

                if threats is not None:
                    threat_list = threats['page_items']

                    # sort earliest to latest
                    threat_list.reverse()

                    # pagination
                    if threats['total_number_of_items']:
                        page_number = page_number + 1
                        total_items = int(threats['total_number_of_items'])
                        if total_items < (page_size * page_number):
                            more_threats = False

                else:
                    self.logger.error('Failed to retrieve the threat list from Cylance for tenant: '
                                      + tenant)
                    # TODO insert trigger here
                    continue

                for threat in threat_list:

                    # attempt to extract time information for our log
                    threat_date = datetime.strptime(threat['last_found'], '%Y-%m-%dT%H:%M:%S')

                    if threat_date > last_timestamp:

                        fact_data = {
                            'response': threat,
                            'filePath': 'Unknown'
                        }

                        # try to parse the fields
                        threat_url = threat.get('sha256', None)

                        # get threat URL
                        if threat_url:
                            threat_url_response = client_instance.get_threat_url(threat_url)

                        if threat_url_response:
                            fact_data.update({'filePath': threat_url_response['url']})
                        else:
                            fact_data.update({'filePath': 'Unknown'})

                        self.sensor_service.dispatch(trigger=self._trigger_ref, payload=fact_data)

                        self._set_last_timestamp(self._set_last_timestamp(threat_date), tenant)

    def cleanup(self):
        pass

    def add_trigger(self, trigger):
        pass

    def update_trigger(self, trigger):
        pass

    def remove_trigger(self, trigger):
        pass

    def _set_last_timestamp(self, timestamp, tenant):
        self._timestamps[tenant] = timestamp
        self._logger.info('Setting timestamp for {} to {}'.format(tenant, timestamp))

        if hasattr(self.sensor_service, 'set_value'):
            self.sensor_service.set_value(name=tenant + '.last_timestamp', value=timestamp)

    def _get_last_timestamp(self, tenant):
        stored = self.sensor_service.get_value(tenant + '.last_timestamp')

        if stored:
            return stored

        return datetime.utcnow() - timedelta(days=1)
