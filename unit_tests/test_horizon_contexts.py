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

from mock import MagicMock, patch, call
import horizon_contexts
from contextlib import contextmanager

from test_utils import (
    CharmTestCase
)

TO_PATCH = [
    'config',
    'relation_get',
    'relation_ids',
    'related_units',
    'log',
    'get_cert',
    'b64decode',
    'context_complete',
    'local_unit',
    'unit_get',
    'pwgen',
]


@contextmanager
def patch_open():
    '''Patch open() to allow mocking both open() itself and the file that is
    yielded.

    Yields the mock for "open" and "file", respectively.'''
    mock_open = MagicMock(spec=open)
    mock_file = MagicMock(spec=file)

    @contextmanager
    def stub_open(*args, **kwargs):
        mock_open(*args, **kwargs)
        yield mock_file

    with patch('__builtin__.open', stub_open):
        yield mock_open, mock_file


class TestHorizonContexts(CharmTestCase):

    def setUp(self):
        super(TestHorizonContexts, self).setUp(horizon_contexts, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.pwgen.return_value = "secret"

    def test_Apachecontext(self):
        self.assertEqual(horizon_contexts.ApacheContext()(),
                         {'http_port': 70, 'https_port': 433,
                          'enforce_ssl': False})

    def test_Apachecontext_enforce_ssl(self):
        self.test_config.set('enforce-ssl', True)
        self.get_cert.return_value = ('cert', 'key')
        self.assertEquals(horizon_contexts.ApacheContext()(),
                          {'http_port': 70, 'https_port': 433,
                           'enforce_ssl': True})

    def test_Apachecontext_enforce_ssl_no_cert(self):
        self.test_config.set('enforce-ssl', True)
        self.get_cert.return_value = (None, 'key')
        self.assertEquals(horizon_contexts.ApacheContext()(),
                          {'http_port': 70, 'https_port': 433,
                           'enforce_ssl': False})

    @patch.object(horizon_contexts, 'get_ca_cert', lambda: None)
    @patch('os.chmod')
    def test_ApacheSSLContext_enabled(self, _chmod):
        self.get_cert.return_value = ('cert', 'key')
        self.b64decode.side_effect = ['cert', 'key']
        with patch_open() as (_open, _file):
            self.assertEqual(horizon_contexts.ApacheSSLContext()(),
                             {'ssl_configured': True,
                              'ssl_cert': '/etc/ssl/certs/dashboard.cert',
                              'ssl_key': '/etc/ssl/private/dashboard.key'})
            _open.assert_has_calls([
                call('/etc/ssl/certs/dashboard.cert', 'w'),
                call('/etc/ssl/private/dashboard.key', 'w')
            ])
            _file.write.assert_has_calls([
                call('cert'),
                call('key')
            ])
        # Security check on key permissions
        _chmod.assert_called_with('/etc/ssl/private/dashboard.key', 0o600)

    @patch.object(horizon_contexts, 'get_ca_cert', lambda: None)
    def test_ApacheSSLContext_disabled(self):
        self.get_cert.return_value = (None, None)
        self.assertEqual(horizon_contexts.ApacheSSLContext()(),
                         {'ssl_configured': False})

    def test_HorizonContext_defaults(self):
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_default_domain(self):
        self.test_config.set('default-domain', 'example_domain')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": "example_domain",
                          "multi_domain": False
                          }
                         )

    def test_HorizonContext_debug(self):
        self.test_config.set('debug', 'yes')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': True,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_ubuntu_theme(self):
        self.test_config.set('ubuntu-theme', 'False')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': False,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_default_theme(self):
        self.test_config.set('ubuntu-theme', 'False')
        self.test_config.set('default-theme', 'material')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': False,
                          'default_theme': 'material',
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_default_theme_true(self):
        self.test_config.set('ubuntu-theme', 'true')
        self.assertTrue(horizon_contexts.HorizonContext()()['ubuntu_theme'])

    def test_HorizonContext_compression(self):
        self.test_config.set('offline-compression', 'no')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': False, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_role(self):
        self.test_config.set('default-role', 'foo')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'foo', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_webroot(self):
        self.test_config.set('webroot', '/')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_panels(self):
        self.test_config.set('neutron-network-dvr', True)
        self.test_config.set('neutron-network-l3ha', True)
        self.test_config.set('neutron-network-lb', True)
        self.test_config.set('neutron-network-firewall', True)
        self.test_config.set('neutron-network-vpn', True)
        self.test_config.set('cinder-backup', True)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": True,
                          "neutron_network_l3ha": True,
                          "neutron_network_lb": True,
                          "neutron_network_firewall": True,
                          "neutron_network_vpn": True,
                          "cinder_backup": True,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_password_retrieve(self):
        self.test_config.set('password-retrieve', True)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": True,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_HorizonContext_customization_module(self):
        self.test_config.set('customization-module', 'customization.py')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': 'customization.py',
                          'default_role': 'Member', 'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'virtualenv': None,
                          'secret': 'secret',
                          'support_profile': None,
                          "neutron_network_dvr": False,
                          "neutron_network_l3ha": False,
                          "neutron_network_lb": False,
                          "neutron_network_firewall": False,
                          "neutron_network_vpn": False,
                          "cinder_backup": False,
                          "password_retrieve": False,
                          "default_domain": None,
                          "multi_domain": True
                          }
                         )

    def test_IdentityServiceContext_not_related(self):
        self.relation_ids.return_value = []
        self.context_complete.return_value = False
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {})

    def test_IdentityServiceContext_no_units(self):
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = []
        self.context_complete.return_value = False
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {})

    @patch("horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_no_data(self, mock_format_ipv6_addr):
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar']
        self.relation_get.side_effect = self.test_relation.get
        self.context_complete.return_value = False
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {})

    @patch("horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_data(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.return_value = "foo"
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'service_host': 'foo', 'service_port': 5000,
                          'api_version': '2', 'service_protocol': 'http'})

    @patch("horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_single_region(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.return_value = "foo"
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'region': 'regionOne'})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'service_host': 'foo', 'service_port': 5000,
                          'api_version': '2', 'service_protocol': 'http'})

    @patch("horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_multi_region(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.return_value = "foo"
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'region': 'regionOne regionTwo'})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'service_host': 'foo', 'service_port': 5000,
                          'service_protocol': 'http', 'api_version': '2',
                          'regions': [{'endpoint': 'http://foo:5000/v2.0',
                                       'title': 'regionOne'},
                                      {'endpoint': 'http://foo:5000/v2.0',
                                       'title': 'regionTwo'}]})

    @patch("horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_api3(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.return_value = "foo"
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({
            'service_host': 'foo',
            'service_port': 5000,
            'region': 'regionOne',
            'api_version': '3',
            'admin_domain_id': 'admindomainid'})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(), {
            'service_host': 'foo',
            'service_port': 5000,
            'api_version': '3',
            'admin_domain_id': 'admindomainid',
            'service_protocol': 'http'})

    @patch("horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_api3_missing(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.return_value = "foo"
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({
            'service_host': 'foo',
            'service_port': 5000,
            'region': 'regionOne',
            'api_version': '3'})
        self.context_complete.return_value = False
        self.assertEqual(horizon_contexts.IdentityServiceContext()(), {})

    def test_IdentityServiceContext_endpoint_type(self):
        self.test_config.set('endpoint-type', 'internalURL')
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'primary_endpoint': 'internalURL'})

    def test_IdentityServiceContext_multi_endpoint_types(self):
        self.test_config.set('endpoint-type', 'internalURL,publicURL')
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'primary_endpoint': 'internalURL',
                          'secondary_endpoint': 'publicURL'})

    def test_IdentityServiceContext_invalid_endpoint_type(self):
        self.test_config.set('endpoint-type', 'this_is_bad')
        with self.assertRaises(Exception):
            horizon_contexts.IdentityServiceContext()()

    def test_HorizonHAProxyContext_no_cluster(self):
        self.relation_ids.return_value = []
        self.local_unit.return_value = 'openstack-dashboard/0'
        self.unit_get.return_value = "10.5.0.1"
        with patch_open() as (_open, _file):
            self.assertEqual(horizon_contexts.HorizonHAProxyContext()(),
                             {'units': {'openstack-dashboard-0': '10.5.0.1'},
                              'service_ports': {'dash_insecure': [80, 70],
                                                'dash_secure': [443, 433]},
                              'prefer_ipv6': False})
            _open.assert_called_with('/etc/default/haproxy', 'w')
            self.assertTrue(_file.write.called)

    def test_HorizonHAProxyContext_clustered(self):
        self.relation_ids.return_value = ['cluster:0']
        self.related_units.return_value = [
            'openstack-dashboard/1', 'openstack-dashboard/2'
        ]
        self.relation_get.side_effect = ['10.5.0.2', '10.5.0.3']
        self.local_unit.return_value = 'openstack-dashboard/0'
        self.unit_get.return_value = "10.5.0.1"
        with patch_open() as (_open, _file):
            self.assertEqual(horizon_contexts.HorizonHAProxyContext()(),
                             {'units': {'openstack-dashboard-0': '10.5.0.1',
                                        'openstack-dashboard-1': '10.5.0.2',
                                        'openstack-dashboard-2': '10.5.0.3'},
                              'service_ports': {'dash_insecure': [80, 70],
                                                'dash_secure': [443, 433]},
                              'prefer_ipv6': False})
            _open.assert_called_with('/etc/default/haproxy', 'w')
            self.assertTrue(_file.write.called)

    def test_RouterSettingContext(self):
        self.test_config.set('profile', 'cisco')
        self.assertEqual(horizon_contexts.RouterSettingContext()(),
                         {'disable_router': False, })
        self.test_config.set('profile', None)
        self.assertEqual(horizon_contexts.RouterSettingContext()(),
                         {'disable_router': True, })

    def test_LocalSettingsContext(self):
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': 99,
                                          'local-settings': 'FOO = True'},
                                         {'priority': 60,
                                          'local-settings': 'BAR = False'}]

        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin-too/0\n'
                                       'BAR = False',
                                       '# horizon-plugin/0\n'
                                       'FOO = True']})
