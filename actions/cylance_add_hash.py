import json

from base import CylanceBaseAction
from st2common.runners.base_action import Action


class CylanceAddHash(CylanceBaseAction):
    """Add a hash value to a Quarantine or Safe List"""
    def run(self, hash_value, list_type, category=None, reason=None):

        logger = self.logger

        response = self.cylance.add_hash_to_list(hash_value, list_type, category, reason)
        if response:

            response_dict = json.loads(response.content)
            fact_data = {
                'sha256': response_dict['sha256'],
                'category': response_dict['category'],
                'listType': response_dict['list_type'],
                'reason': response_dict['reason'],
                'action': "Successfully added hash to the specified list."
            }

            return True, fact_data
        else:
            #return False, "Hash could not be added to the specified list."
            return False, response
