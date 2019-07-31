import json

from base import CylanceBaseAction
from st2common.runners.base_action import Action


class CylanceChangePolicy(CylanceBaseAction):
    """Get Threat Information given a Hash Value"""
    def run(self, device_name, policy_name):

        response = self.cylance.update_device_policy(device_name, policy_name)

        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return False, response[1]

            fact_data = {
                'response': response_dict
            }

            return True, fact_data
        else:
            return False, "Cylance could not retrieve threat information given the provided hash value"

