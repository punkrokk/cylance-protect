from lib.base import CylanceBaseAction


class CylanceGetThreatURL(CylanceBaseAction):
    """Get Threat Device Information given a Hash Value"""
    def run(self, sha256):

        response = self.cylance.get_threat_url(sha256)

        if response[0]:

            try:
                response_dict = response[1].json()
            except:
                return False, 'Could not parse JSON response'

            return True, response_dict
        else:
            return False, "Cylance could not retrieve threat information given the provided hash " \
                          "value"
