# Copyright 2022 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

from unittest.mock import patch, MagicMock

os.environ['JUJU_UNIT_NAME'] = 'openstack-dashboard'

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
sys.modules['apt'] = MagicMock()
sys.modules['apt_pkg'] = MagicMock()

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    with patch('hooks.horizon_utils.register_configs') as register_configs:
        import actions.package_upgrade as package_upgrade

from unit_tests.test_utils import CharmTestCase

TO_PATCH = [
    'config_changed',
    'do_openstack_upgrade',
]


class TestHorizonUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestHorizonUpgradeActions, self).setUp(package_upgrade,
                                                     TO_PATCH)

    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_package_upgrade_success(self, upgrade_avail,
                                     action_set):
        upgrade_avail.return_value = False
        package_upgrade.package_upgrade()
        self.assertTrue(self.do_openstack_upgrade.called)

    @patch('charmhelpers.contrib.openstack.utils.action_set')
    @patch('charmhelpers.contrib.openstack.utils.openstack_upgrade_available')
    def test_package_upgrade_failure(self, upgrade_avail,
                                     action_set):
        upgrade_avail.return_value = True
        package_upgrade.package_upgrade()
        self.assertFalse(self.do_openstack_upgrade.called)
