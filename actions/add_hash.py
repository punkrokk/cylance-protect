from lib.base import CylanceBaseAction


class CylanceAddHash(CylanceBaseAction):
    """Add a hash value to a Quarantine or Safe List"""
    def run(self, hash_value, list_type, category=None, reason=None):

        category = category if category else 'Security Software'
        reason = reason if reason else None

        response = self.cylance.add_hash_to_list(hash_value, list_type, category, reason)

        if response[0]:
            return True, {'result': 'Successfully added hash to the specified list'}
        else:
            return False, {'result': "Hash could not be added to the specified list."}
