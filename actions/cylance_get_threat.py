import json

from base import CylanceBaseAction
from st2common.runners.base_action import Action


class CylanceGetThreat(CylanceBaseAction):
    """Get Threat Information given a Hash Value"""
    def run(self, sha256):

        response = self.cylance.get_threat(sha256)

        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return False, 'Could not parse JSON response'

            fact_data = {
                'response': response_dict
            }

            return True, fact_data
        else:
            return False, "Cylance could not retrieve threat information given the provided hash value"

