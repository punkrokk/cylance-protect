from lib.base import CylanceBaseAction


class CylanceGetThreats(CylanceBaseAction):
    """Get Threat Information given a Hash Value"""
    def run(self, page, page_size):

        response = self.cylance.get_threats(page, page_size)

        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return False, 'Could not parse JSON response'

            return True, response_dict
        else:
            return False, "Cylance could not retrieve the threat list"
