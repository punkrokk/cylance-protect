from lib.base import CylanceBaseAction


class CylanceGetThreatDevices(CylanceBaseAction):
    """Get Threat Device Information given a Hash Value"""
    def run(self, tenant, sha256):

        if tenant not in self.tenants:
            response = {
                "Tenant not found.  Must be one of: " + str(self.tenants)
            }
            return False, response

        cylance_instance = self.instances[tenant]

        response = cylance_instance.get_threat_devices(sha256)

        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return False, {'result': 'Could not parse JSON response'}

            return True, {'result': response_dict}
        else:
            return False, {'result': "Cylance could not retrieve threat information given the "
                                     "provided hash value"}
