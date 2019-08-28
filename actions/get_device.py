from lib.base import CylanceBaseAction


class CylanceGetDevice(CylanceBaseAction):
    """Get Device Information given a Device Name"""
    def run(self, device_name):

        response = self.cylance.get_device(device_name)
        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return False, 'Could not parse JSON response'

            return True, response_dict
        else:
            return False, "Hash could not retrieve device information given the provided name"
