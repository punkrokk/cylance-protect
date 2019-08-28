from lib.base import CylanceBaseAction


class CylanceGetDevice(CylanceBaseAction):
    """Get Device Information given a Device Name"""
    def run(self, device_name):

        response = self.cylance.get_device(device_name)
        if response:

            return True, response
        else:
            return False, "Hash could not retrieve device information given the provided name"
