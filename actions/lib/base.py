from st2common.runners.base_action import Action
from cylance import CylanceProtectClient


__all__ = [
    'CylanceBaseAction'
]


class CylanceBaseAction(Action):
    """Things common to Cylance Protect action class construction"""
    def __init__(self, config):
        super(CylanceBaseAction, self).__init__(config=config)

        self.tenants = []
        self.instances = {}

        credentials = self.config.get('tenants')

        for tenant, creds in credentials.items():
            tenant_value = creds.get('tenant_value', None)
            app_id = creds.get('app_id', None)
            app_secret = creds.get('app_secret', None)

            try:
                self.instances[tenant] = CylanceProtectClient(tenant_value, app_id, app_secret,
                                                              logger=self.logger)
            except ValueError as e:
                self.logger.error(e)

            self.tenants.append(tenant)
