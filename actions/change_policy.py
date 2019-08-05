from lib.base import CylanceBaseAction


class CylanceChangePolicy(CylanceBaseAction):
    """Get Threat Information given a Hash Value"""
    def run(self, device_name, policy_name):

        response = self.cylance.update_device_policy(device_name, policy_name)

        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return True, 'Policy successfully changed'

            fact_data = {
                'response': response_dict
            }

            return True, fact_data
        else:
            return False, "Cylance could not change the device's policy as given"
