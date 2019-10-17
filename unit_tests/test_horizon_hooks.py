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

import sys

from mock import MagicMock, patch, call
from unit_tests.test_utils import CharmTestCase

# python-apt is not installed as part of test-requirements but is imported by
# some charmhelpers modules so create a fake import.
sys.modules['apt'] = MagicMock()

import hooks.horizon_utils as utils

with patch('charmhelpers.contrib.hardening.harden.harden') as mock_dec:
    mock_dec.side_effect = (lambda *dargs, **dkwargs: lambda f:
                            lambda *args, **kwargs: f(*args, **kwargs))

    import hooks.horizon_hooks as hooks

RESTART_MAP = utils.restart_map()

TO_PATCH = [
    'config',
    'relation_set',
    'relation_get',
    'configure_installation_source',
    'apt_update',
    'apt_install',
    'filter_installed_packages',
    'open_port',
    'CONFIGS',
    'relation_ids',
    'enable_ssl',
    'openstack_upgrade_available',
    'do_openstack_upgrade',
    'save_script_rc',
    'install_ca_cert',
    'unit_get',
    'log',
    'execd_preinstall',
    'b64decode',
    'os_release',
    'update_nrpe_config',
    'lsb_release',
    'status_set',
    'services',
    'service_restart',
    'remove_old_packages',
    'generate_ha_relation_data',
    'resolve_address',
    'register_configs',
]


def passthrough(value):
    return value


class TestHorizonHooks(CharmTestCase):

    def setUp(self):
        super(TestHorizonHooks, self).setUp(hooks, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.b64decode.side_effect = passthrough
        hooks.hooks._config_save = False
        hooks.CONFIGS = None

    def _call_hook(self, hookname):
        hooks.hooks.execute([
            'hooks/{}'.format(hookname)])

    @patch.object(hooks, 'register_configs')
    def test_resolve_CONFIGS(self, _register_configs):
        _register_configs.return_value = 'new configs'
        self.assertEqual(
            hooks.resolve_CONFIGS(),
            'new configs')
        _register_configs.assert_called_once_with()

    @patch.object(hooks, 'register_configs')
    def test_resolve_CONFIGS_existing_configs(self, _register_configs):
        hooks.CONFIGS = 'existing stuff'
        self.assertEqual(
            hooks.resolve_CONFIGS(),
            'existing stuff')
        self.assertFalse(_register_configs.called)

    @patch.object(hooks, 'register_configs')
    def test_resolve_CONFIGS_existing_configs_force(self, _register_configs):
        _register_configs.return_value = 'new configs from force'
        hooks.CONFIGS = 'existing stuff'
        self.assertEqual(
            hooks.resolve_CONFIGS(force_update=True),
            'new configs from force')
        _register_configs.assert_called_once_with()

    @patch.object(hooks, 'determine_packages')
    def test_install_hook(self, _determine_packages):
        _determine_packages.return_value = []
        self.filter_installed_packages.return_value = ['foo', 'bar']
        self.os_release.return_value = 'icehouse'
        self._call_hook('install.real')
        self.configure_installation_source.assert_called_with('distro')
        self.apt_update.assert_called_with(fatal=True)
        self.apt_install.assert_called_with(['foo', 'bar'], fatal=True)

    @patch.object(hooks, 'determine_packages')
    def test_install_hook_precise(self, _determine_packages):
        _determine_packages.return_value = []
        self.filter_installed_packages.return_value = ['foo', 'bar']
        self.os_release.return_value = 'icehouse'
        self.lsb_release.return_value = {'DISTRIB_CODENAME': 'precise'}
        self._call_hook('install.real')
        self.configure_installation_source.assert_called_with('distro')
        self.apt_update.assert_called_with(fatal=True)
        calls = [
            call('python-six', fatal=True),
            call(['foo', 'bar'], fatal=True),
        ]
        self.apt_install.assert_has_calls(calls)

    @patch.object(hooks, 'determine_packages')
    def test_install_hook_icehouse_pkgs(self,
                                        _determine_packages):
        _determine_packages.return_value = []
        self.os_release.return_value = 'icehouse'
        self._call_hook('install.real')
        for pkg in ['nodejs', 'node-less']:
            self.assertFalse(
                pkg in self.filter_installed_packages.call_args[0][0]
            )
        self.assertTrue(self.apt_install.called)

    @patch.object(hooks, 'determine_packages')
    def test_install_hook_pre_icehouse_pkgs(self,
                                            _determine_packages):
        _determine_packages.return_value = []
        self.os_release.return_value = 'grizzly'
        self._call_hook('install.real')
        for pkg in ['nodejs', 'node-less']:
            self.assertTrue(
                pkg in self.filter_installed_packages.call_args[0][0]
            )
        self.assertTrue(self.apt_install.called)

    @patch('time.sleep')
    @patch('hooks.horizon_hooks.check_custom_theme')
    @patch.object(hooks, 'determine_packages')
    @patch.object(utils, 'path_hash')
    @patch.object(utils, 'service')
    def test_upgrade_charm_hook(self, _service, _hash,
                                _determine_packages,
                                _custom_theme,
                                _sleep):
        self.remove_old_packages.return_value = False
        _determine_packages.return_value = []
        side_effects = []
        [side_effects.append(None) for f in RESTART_MAP.keys()]
        [side_effects.append('bar') for f in RESTART_MAP.keys()]
        _hash.side_effect = side_effects
        self.filter_installed_packages.return_value = ['foo']
        self._call_hook('upgrade-charm')
        self.apt_install.assert_called_with(['foo'], fatal=True)
        self.assertTrue(self.register_configs().write_all.called)
        ex = [
            call('stop', 'apache2'),
            call('stop', 'memcached'),
            call('stop', 'haproxy'),
            call('start', 'apache2'),
            call('start', 'memcached'),
            call('start', 'haproxy'),
        ]
        self.assertEqual(ex, _service.call_args_list)
        self.assertTrue(_custom_theme.called)
        # we mock out time.sleep, as otherwise the called code in
        # restart_on_change actually sleeps for 9 seconds,
        _sleep.assert_called()

    @patch('time.sleep')
    @patch('hooks.horizon_hooks.check_custom_theme')
    @patch.object(hooks, 'determine_packages')
    @patch.object(utils, 'path_hash')
    @patch.object(utils, 'service')
    def test_upgrade_charm_hook_purge(self, _service, _hash,
                                      _determine_packages,
                                      _custom_theme,
                                      _sleep):
        self.remove_old_packages.return_value = True
        self.services.return_value = ['apache2']
        _determine_packages.return_value = []
        side_effects = []
        [side_effects.append(None) for f in RESTART_MAP.keys()]
        [side_effects.append('bar') for f in RESTART_MAP.keys()]
        _hash.side_effect = side_effects
        self.filter_installed_packages.return_value = ['foo']
        self._call_hook('upgrade-charm')
        self.remove_old_packages.assert_called_once_with()
        self.service_restart.assert_called_once_with('apache2')

    def test_ha_joined(self):
        self.generate_ha_relation_data.return_value = {'rel_data': 'data'}
        self._call_hook('ha-relation-joined')
        self.relation_set.assert_called_once_with(
            rel_data='data',
            relation_id=None)

    @patch('hooks.horizon_hooks.check_custom_theme')
    @patch('hooks.horizon_hooks.keystone_joined')
    def test_config_changed_no_upgrade(self, _joined, _custom_theme):
        def relation_ids_side_effect(rname):
            return {
                'websso-trusted-dashboard': [
                    'websso-trusted-dashboard:0',
                    'websso-trusted-dashboard:1',
                ],
                'identity-service': [
                    'identity/0',
                ],
                'certificates': [],
                'ha': [],
            }[rname]
        self.relation_ids.side_effect = relation_ids_side_effect

        def config_side_effect(key):
            return {
                'ssl-key': 'somekey',
                'enforce-ssl': True,
                'dns-ha': True,
                'os-public-hostname': 'dashboard.intranet.test',
                'prefer-ipv6': False,
                'action-managed-upgrade': False,
                'webroot': '/horizon',
            }[key]
        self.config.side_effect = config_side_effect
        self.openstack_upgrade_available.return_value = False
        self._call_hook('config-changed')
        _joined.assert_called_with('identity/0')
        self.openstack_upgrade_available.assert_called_with(
            'openstack-dashboard'
        )
        self.assertTrue(self.enable_ssl.called)
        self.do_openstack_upgrade.assert_not_called()
        self.assertTrue(self.save_script_rc.called)
        self.assertTrue(self.register_configs().write_all.called)
        self.open_port.assert_has_calls([call(80), call(443)])
        self.assertTrue(_custom_theme.called)

    @patch('hooks.horizon_hooks.check_custom_theme')
    def test_config_changed_do_upgrade(self, _custom_theme):
        config_mock1 = MagicMock()
        config_mock2 = MagicMock()
        config_mocks = [config_mock2, config_mock1]

        def _register_configs():
            return config_mocks.pop()
        self.register_configs.side_effect = _register_configs
        self.relation_ids.return_value = []
        self.test_config.set('openstack-origin', 'cloud:precise-grizzly')
        self.openstack_upgrade_available.return_value = True
        self._call_hook('config-changed')
        self.assertTrue(self.do_openstack_upgrade.called)
        self.assertTrue(_custom_theme.called)
        # Assert that the second mock is used for writing config as
        # that shows that CONFIGS was refreshed post-upgrade.
        config_mock2.write_all.assert_called_once_with()

    def test_keystone_joined_in_relation(self):
        self._call_hook('identity-service-relation-joined')
        self.relation_set.assert_called_with(
            relation_id=None, service='None', region='None',
            public_url='None', admin_url='None', internal_url='None',
            requested_roles='Member'
        )

    def test_keystone_joined_not_in_relation(self):
        hooks.keystone_joined('identity/0')
        self.relation_set.assert_called_with(
            relation_id='identity/0', service='None', region='None',
            public_url='None', admin_url='None', internal_url='None',
            requested_roles='Member'
        )

    def test_keystone_changed_no_cert(self):
        self.relation_get.return_value = None
        self._call_hook('identity-service-relation-changed')
        self.register_configs().write_all.assert_called_with()
        self.install_ca_cert.assert_not_called()

    def test_keystone_changed_cert(self):
        self.relation_get.return_value = 'certificate'
        self._call_hook('identity-service-relation-changed')
        self.register_configs().write_all.assert_called_with()
        self.install_ca_cert.assert_called_with('certificate')

    def test_cluster_departed(self):
        self._call_hook('cluster-relation-departed')
        self.register_configs().write.assert_called_with(
            '/etc/haproxy/haproxy.cfg')

    def test_cluster_changed(self):
        self._call_hook('cluster-relation-changed')
        self.register_configs().write.assert_called_with(
            '/etc/haproxy/haproxy.cfg')

    def test_website_joined(self):
        self.unit_get.return_value = '192.168.1.1'
        self._call_hook('website-relation-joined')
        self.relation_set.assert_called_with(port=70, hostname='192.168.1.1')

    @patch.object(hooks, 'os_release')
    def test_dashboard_config_joined(self, _os_release):
        _os_release.return_value = 'vivid'
        self._call_hook('dashboard-plugin-relation-joined')
        self.relation_set.assert_called_with(
            release='vivid',
            bin_path='/usr/bin',
            openstack_dir='/usr/share/openstack-dashboard',
            relation_id=None
        )

    def test_websso_fid_service_provider_changed(self):
        self._call_hook('websso-fid-service-provider-relation-changed')
        self.register_configs().write_all.assert_called_with()

    def test_websso_trusted_dashboard_changed_no_tls(self):
        def relation_ids_side_effect(rname):
            return {
                'websso-trusted-dashboard': [
                    'websso-trusted-dashboard:0',
                    'websso-trusted-dashboard:1',
                ],
                'certificates': [],
            }[rname]
        self.relation_ids.side_effect = relation_ids_side_effect
        hostname = 'dashboard.intranet.test'

        def config_side_effect(key):
            return {
                'ssl-key': None,
                'enforce-ssl': None,
                'dns-ha': None,
                'os-public-hostname': hostname,
                'webroot': '/horizon',
            }[key]
        self.config.side_effect = config_side_effect
        self.resolve_address.return_value = hostname
        self._call_hook('websso-trusted-dashboard-relation-changed')
        self.relation_set.assert_has_calls([
            call(relation_id='websso-trusted-dashboard:0',
                 relation_settings={
                     "scheme": "http://",
                     "hostname": "dashboard.intranet.test",
                     "path": "/horizon/auth/websso/",
                 }),
            call(relation_id='websso-trusted-dashboard:1',
                 relation_settings={
                     "scheme": "http://",
                     "hostname": "dashboard.intranet.test",
                     "path": "/horizon/auth/websso/",
                 }),
        ])

    def test_websso_trusted_dashboard_changed_tls_certificates_relation(self):
        def relation_ids_side_effect(rname):
            return {
                'websso-trusted-dashboard': [
                    'websso-trusted-dashboard:0',
                    'websso-trusted-dashboard:1',
                ],
                'certificates': ['certificates:9'],
            }[rname]
        self.relation_ids.side_effect = relation_ids_side_effect
        hostname = 'dashboard.intranet.test'

        def config_side_effect(key):
            return {
                'ssl-key': None,
                'enforce-ssl': None,
                'dns-ha': None,
                'os-public-hostname': hostname,
                'webroot': '/horizon'
            }[key]
        self.config.side_effect = config_side_effect
        self.resolve_address.return_value = hostname
        self._call_hook('websso-trusted-dashboard-relation-changed')
        self.relation_set.assert_has_calls([
            call(relation_id='websso-trusted-dashboard:0',
                 relation_settings={
                     "scheme": "https://",
                     "hostname": "dashboard.intranet.test",
                     "path": "/horizon/auth/websso/",
                 }),
            call(relation_id='websso-trusted-dashboard:1',
                 relation_settings={
                     "scheme": "https://",
                     "hostname": "dashboard.intranet.test",
                     "path": "/horizon/auth/websso/",
                 }),
        ])

    def test_websso_trusted_dashboard_changed_ssl_config(self):
        def relation_ids_side_effect(rname):
            return {
                'websso-trusted-dashboard': [
                    'websso-trusted-dashboard:0',
                    'websso-trusted-dashboard:1',
                ],
                'certificates': [],
            }[rname]
        self.relation_ids.side_effect = relation_ids_side_effect
        hostname = 'dashboard.intranet.test'

        def config_side_effect(key):
            return {
                'ssl-key': 'somekey',
                'enforce-ssl': True,
                'dns-ha': True,
                'os-public-hostname': hostname,
                'webroot': '/horizon',
            }[key]
        self.config.side_effect = config_side_effect
        self.resolve_address.return_value = hostname
        self._call_hook('websso-trusted-dashboard-relation-changed')
        self.relation_set.assert_has_calls([
            call(relation_id='websso-trusted-dashboard:0',
                 relation_settings={
                     "scheme": "https://",
                     "hostname": "dashboard.intranet.test",
                     "path": "/horizon/auth/websso/",
                 }),
            call(relation_id='websso-trusted-dashboard:1',
                 relation_settings={
                     "scheme": "https://",
                     "hostname": "dashboard.intranet.test",
                     "path": "/horizon/auth/websso/",
                 }),
        ])

    @patch.object(hooks, 'service_reload')
    @patch.object(hooks, 'process_certificates')
    def test_certs_changed(self, _process_certificates, _service_reload):
        self._call_hook('certificates-relation-changed')
        _process_certificates.assert_called_with(
            'horizon', None, None)
        self.register_configs().write_all.assert_called_with()
        _service_reload.assert_called_with('apache2')
        self.enable_ssl.assert_called_with()
