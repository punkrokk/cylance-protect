import json

from base import CylanceBaseAction
from st2common.runners.base_action import Action
from cylance import CylanceProtectClient


class CylanceAddHash(Action):
    """Add a hash value to a Quarantine List"""
    def run(self, hash_value, list_type, category=None, reason=None):

        try:
            cylance = CylanceProtectClient(tenant_value=tenant_value, app_id=app_id, app_secret=app_secret)
        except (ValueError, KeyError) as e:
            self.logger.error(e.__str__())
            sys.exit(1)

        response = cylance.add_hash_to_list(hash_value, list_type, category, reason)

        fact_data = {}

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
