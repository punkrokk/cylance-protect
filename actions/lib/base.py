from st2common.runners.base_action import Action
from cylance import CylanceProtectClient


__all__ = [
    'CylanceBaseAction'
]


class CylanceBaseAction(Action):
    """Things common to Cylance Optics action class construction"""
    def __init__(self, config):
        super(CylanceBaseAction, self).__init__(config=config)
        tenant_value = self.config.get('tenant_value', None)
        app_id = self.config.get('app_id', None)
        app_secret = self.config.get('app_secret', None)

        self.logger.debug(config)

        try:
            self.cylance = CylanceProtectClient(tenant_value, app_id, app_secret)
        except ValueError as e:
            self.logger.error(e)
