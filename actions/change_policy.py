from lib.base import CylanceBaseAction


class CylanceChangePolicy(CylanceBaseAction):
    """Change a Policy on a Specified Device"""
    def run(self, tenant, device_name, policy_name):

        if tenant not in self.tenants:
            response = {
                "Tenant not found.  Must be one of: " + str(self.tenants)
            }
            return False, response

        cylance_instance = self.instances[tenant]

        response = cylance_instance.update_device_policy(device_name, policy_name)

        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return True, {'result': 'Policy successfully changed'}

            return True, {'result': response_dict}
        else:
            return False, {'result': 'Cylance could not change the device\'s policy as given'}
