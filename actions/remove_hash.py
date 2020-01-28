
from lib.base import CylanceBaseAction


class CylanceRemoveHash(CylanceBaseAction):
    """Remove a hash value from a Quarantine or Safe List"""
    def run(self, tenant, hash_value, list_type):

        if tenant not in self.tenants:
            response = {
                "Tenant not found.  Must be one of: " + str(self.tenants)
            }
            return False, response

        cylance_instance = self.instances[tenant]

        response = cylance_instance.remove_hash_from_list(hash_value, list_type)

        if response[0]:
            # the response only returns success or failure
            return True, {'result': 'Successfully removed hash from the specified list.'}
        else:
            return False, {'result': "Hash could not be removed from the specified list."}
