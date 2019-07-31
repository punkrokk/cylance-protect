import json

from base import CylanceBaseAction
from st2common.runners.base_action import Action


class CylanceGetDevice(CylanceBaseAction):
    """Get Device Information given a Device Name"""
    def run(self, device_name):

        response = self.cylance.get_device(device_name)
        if response[0]:

            try:
                response_dict = response[1].json()
                fact_data = {
                    'id': response_dict.get('id', None),
                    'name': response_dict.get('name', None),
                    'deviceHostName': response_dict.get('host_name', None),
                    'osName': response_dict.get('os_version', None),
                    'state': response_dict.get('state', None),
                    'agentVersion': response_dict.get('agent_version', None),
                    'policyName': response_dict['policy']['name'],
                    'policyRuleId': response_dict['policy']['id'],
                    'lastLoggedUser': response_dict.get('last_logged_in_user', None),
                    'updateType': response_dict.get('update_type', None),
                    'updateAvailable': response_dict.get('update_available', None),
                    'backgroundDetection': response_dict.get('background_detection', None),
                    'isSafe': response_dict.get('is_safe', None),
                    'dateFirstRegistered': response_dict.get('date_first_registered', None),
                    'dateOffline': response_dict.get('date_offline', None),
                    'dateLastModified': response_dict.get('date_last_modified', None),
                    'ip_address': response_dict['ip_addresses'][0],
                    'mac_address': response_dict['mac_addresses'][0],
                    'distinguishedName': response_dict.get('distinguished_name', None),
                    'originalAlertURL': DEVICE_LINK + response_dict.get('id', '')
                }

                return True, fact_data
            except:
                return False, 'Could not parse JSON response'
        else:
            return False, "Hash could not retrieve device information given the provided name"

