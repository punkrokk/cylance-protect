
import yaml

from st2tests.base import BaseActionTestCase

__all__ = [
    'CylanceBaseActionTestCase',
]


class CylanceBaseActionTestCase(BaseActionTestCase):
    """Shodan Base Action Test Case"""
    __test__ = False

    def setUp(self):
        super(CylanceBaseActionTestCase, self).setUp()

        self.blank_config = self.load_yaml('blank.yaml')
        self.full_api_key = self.load_yaml('full_api_key.yaml')

    def load_yaml(self, filename):
        return yaml.safe_load(self.get_fixture_content(filename))
