from st2common.runners.base_action import Action
from cylance import CylanceProtectClient


__all__ = [
    'CylanceBaseAction'
]


class CylanceBaseAction(Action):
    """Things common to Cylance Protect action class construction"""
    def __init__(self, config):
        super(CylanceBaseAction, self).__init__(config=config)

        # we'll clean any unicode here
        sanitized_config = {}

        for k, v in config.items():
            if isinstance(k, unicode):
                new_key = k.encode('utf-8')
            else:
                new_key = k
            if isinstance(v, unicode):
                new_value = v.encode('utf-8')
            else:
                new_value = v

            sanitized_config[new_key] = new_value

        tenant_value = sanitized_config.get('tenant_value', None)
        app_id = sanitized_config.get('app_id', None)
        app_secret = sanitized_config.get('app_secret', None)

        # uncomment for config debugging
        # self.logger.debug(sanitized_config)

        try:
            self.cylance = CylanceProtectClient(tenant_value, app_id, app_secret)
        except ValueError as e:
            self.logger.error(e)
