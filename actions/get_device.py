from lib.base import CylanceBaseAction


class CylanceGetDevice(CylanceBaseAction):
    """Get Device Information given a Device Name"""
    def run(self, tenant, device_name):

        if tenant not in self.tenants:
            response = {
                "Tenant not found.  Must be one of: " + str(self.tenants)
            }
            return False, response

        cylance_instance = self.instances[tenant]

        response = cylance_instance.get_device(device_name)
        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return False, {'result': 'Could not parse JSON response'}

            return True, {'result': response_dict}
        else:
            return False, {'result': "Could not retrieve device information given the "
                                     "provided name"}
