# Copyright 2016 Canonical Ltd
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

from unittest.mock import call, patch, MagicMock

os.environ['JUJU_UNIT_NAME'] = 'openstack-dashboard'

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
mock_apt = MagicMock()
sys.modules['apt'] = mock_apt
mock_apt.apt_pkg = MagicMock()

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))
    with patch('hooks.horizon_utils.register_configs') as register_configs:
        import actions.openstack_upgrade as openstack_upgrade

from unit_tests.test_utils import CharmTestCase

TO_PATCH = [
    'resolve_CONFIGS',
    'do_action_openstack_upgrade',
    'do_openstack_upgrade',
    'config_changed',
]


class TestHorizonUpgradeActions(CharmTestCase):

    def setUp(self):
        super(TestHorizonUpgradeActions, self).setUp(openstack_upgrade,
                                                     TO_PATCH)

    def test_openstack_upgrade_true(self):

        self.do_action_openstack_upgrade.return_value = True
        self.resolve_CONFIGS.return_value = 'configs'

        openstack_upgrade.openstack_upgrade()

        self.do_action_openstack_upgrade.assert_called_once_with(
            'openstack-dashboard',
            self.do_openstack_upgrade,
            'configs')
        self.resolve_CONFIGS.assert_has_calls([
            call(),
            call(force_update=True),
        ])
        self.config_changed.assert_called_once_with()

    def test_openstack_upgrade_false(self):
        self.do_action_openstack_upgrade.return_value = False
        self.resolve_CONFIGS.return_value = 'configs'

        openstack_upgrade.openstack_upgrade()

        self.do_action_openstack_upgrade.assert_called_once_with(
            'openstack-dashboard',
            self.do_openstack_upgrade,
            'configs')
        self.assertFalse(self.do_openstack_upgrade.called)
        self.assertFalse(self.config_changed.called)
