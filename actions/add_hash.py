from lib.base import CylanceBaseAction


class CylanceAddHash(CylanceBaseAction):
    """Add a hash value to a Quarantine or Safe List"""
    def run(self, tenant, hash_value, list_type, category=None, reason=None):

        if tenant not in self.tenants:
            response = {
                "Tenant not found.  Must be one of: " + str(self.tenants)
            }
            return False, response

        cylance_instance = self.instances[tenant]

        category = category if category else 'Security Software'
        reason = reason if reason else None

        response = cylance_instance.add_hash_to_list(hash_value, list_type, category, reason)

        if response[0]:
            return True, {'result': 'Successfully added hash to the specified list'}
        else:
            return False, {'result': "Hash could not be added to the specified list."}
