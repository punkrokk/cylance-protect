import json

from base import CylanceBaseAction
from st2common.runners.base_action import Action


class CylanceRemoveHash(CylanceBaseAction):
    """Remove a hash value from a Quarantine or Safe List"""
    def run(self, hash_value, list_type):

        response = self.cylance.remove_hash(hash_value, list_type)
        if response[0]:

            # the response only returns success or failure
            fact_data = {
                'action': "Successfully removed hash from the specified list."
            }

            return True, fact_data
        else:
            return False, "Hash could not be removed from the specified list."
