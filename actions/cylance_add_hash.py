import json

from base import CylanceBaseAction
from st2common.runners.base_action import Action


class CylanceAddHash(CylanceBaseAction):
    """Add a hash value to a Quarantine or Safe List"""
    def run(self, hash_value, list_type, category=None, reason=None):

        category = category if category else 'Security Software'
        reason = reason if reason else None

        response = self.cylance.add_hash_to_list(hash_value, list_type, category, reason)
        if response[0]:

            # the response only returns success or failure
            fact_data = {
                'action': "Successfully added hash to the specified list."
            }

            return True, fact_data
        else:
            return False, "Hash could not be added to the specified list."
