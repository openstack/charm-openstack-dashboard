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

from contextlib import contextmanager
import io
from unittest.mock import MagicMock, patch

import hooks.horizon_contexts as horizon_contexts

from unit_tests.test_utils import CharmTestCase
from operator import itemgetter

TO_PATCH = [
    'config',
    'relation_get',
    'relation_ids',
    'related_units',
    'log',
    'https',
    'context_complete',
    'local_unit',
    'get_relation_ip',
    'pwgen',
]


@contextmanager
def patch_open():
    '''Patch open() to allow mocking both open() itself and the file that is
    yielded.

    Yields the mock for "open" and "file", respectively.'''
    mock_open = MagicMock(spec=open)
    mock_file = MagicMock(spec=io.FileIO)

    @contextmanager
    def stub_open(*args, **kwargs):
        mock_open(*args, **kwargs)
        yield mock_file

    with patch('builtins.open', stub_open):
        yield mock_open, mock_file


def with_regions_sorted(identity_service_context, by='title'):
    """Helper method to sort regions in Identity Service Context response.

    :param identity_service_context: callable identity service context
    :param by: regions sorting field name

    :returns: identity service context with sorted regions
    """
    value = identity_service_context()
    value['regions'] = sorted(value['regions'], key=itemgetter(by))
    return value


class TestHorizonContexts(CharmTestCase):

    def setUp(self):
        super(TestHorizonContexts, self).setUp(horizon_contexts, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.pwgen.return_value = "secret"

    def test_Apachecontext(self):
        self.assertEqual(horizon_contexts.ApacheContext()(),
                         {'http_port': 70, 'https_port': 433,
                          'enforce_ssl': False,
                          'hsts_max_age_seconds': 0,
                          'custom_theme': False})

    def test_Apachecontext_enforce_ssl(self):
        self.test_config.set('enforce-ssl', True)
        self.https.return_value = True
        self.assertEquals(horizon_contexts.ApacheContext()(),
                          {'http_port': 70, 'https_port': 433,
                           'enforce_ssl': True,
                           'hsts_max_age_seconds': 0,
                           'custom_theme': False})

    def test_Apachecontext_enforce_ssl_no_cert(self):
        self.test_config.set('enforce-ssl', True)
        self.https.return_value = False
        self.assertEquals(horizon_contexts.ApacheContext()(),
                          {'http_port': 70, 'https_port': 433,
                           'enforce_ssl': False,
                           'hsts_max_age_seconds': 0,
                           'custom_theme': False})

    def test_Apachecontext_hsts_max_age_seconds(self):
        self.test_config.set('enforce-ssl', True)
        self.https.return_value = True
        self.test_config.set('hsts-max-age-seconds', 15768000)
        self.assertEquals(horizon_contexts.ApacheContext()(),
                          {'http_port': 70, 'https_port': 433,
                           'enforce_ssl': True,
                           'hsts_max_age_seconds': 15768000,
                           'custom_theme': False})

    def test_HorizonContext_defaults(self):
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True,
                          'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_default_domain(self):
        self.test_config.set('default-domain', 'example_domain')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": False,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_disable_password_reveal(self):
        self.test_config.set('disable-password-reveal', True)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True,
                          'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": True,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_create_instance_flavor_sort(self):
        self.maxDiff = None
        self.test_config.set('create-instance-flavor-sort-key', 'vcpus')
        self.test_config.set('create-instance-flavor-sort-reverse', True)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True,
                          'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": 'vcpus',
                          "create_instance_flavor_sort_reverse": True,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_enable_router_panel(self):
        self.maxDiff = None
        self.test_config.set('enable-router-panel', False)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True,
                          'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": False,
                          }
                         )

    def test_HorizonContext_enforce_password_check(self):
        self.test_config.set('enforce-password-check', False)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True,
                          'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": False,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_debug(self):
        self.test_config.set('debug', 'yes')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': True,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_ubuntu_theme(self):
        self.test_config.set('ubuntu-theme', 'False')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': False,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_default_theme(self):
        self.test_config.set('ubuntu-theme', 'False')
        self.test_config.set('default-theme', 'material')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': False,
                          'default_theme': 'material',
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
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
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_webroot(self):
        self.test_config.set('webroot', '/')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          "hide_create_volume": False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
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
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_password_retrieve(self):
        self.test_config.set('password-retrieve', True)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_customization_module(self):
        self.test_config.set('customization-module', 'customization.py')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': 'customization.py',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContex_password_autocompletion(self):
        self.maxDiff = 900
        self.test_config.set('allow-password-autocompletion', True)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": True,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_default_create_volume(self):
        self.maxDiff = 900
        self.test_config.set('default-create-volume', False)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": False,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_hide_create_volume(self):
        self.maxDiff = 900
        self.test_config.set('hide-create-volume', True)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': True,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_image_formats(self):
        self.maxDiff = 900
        self.test_config.set('image-formats', 'iso qcow2 raw')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": 'iso qcow2 raw',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_fip_topology_check_disabled(self):
        self.maxDiff = 900
        self.test_config.set('enable-fip-topology-check', False)
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": False,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": None,
                          "site_branding_link": None,
                          "help_url": None,
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_branding(self):
        self.maxDiff = 900
        self.test_config.set('site-branding', 'My Cloud')
        self.test_config.set('site-branding-link',
                             'https://mycloud.example.com/')
        self.test_config.set('help-url', 'https://mycloud.example.com/help')
        self.assertEqual(horizon_contexts.HorizonContext()(),
                         {'compress_offline': True, 'debug': False,
                          'customization_module': '',
                          'webroot': '/horizon',
                          'ubuntu_theme': True,
                          'default_theme': None,
                          'custom_theme': False,
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
                          "multi_domain": True,
                          "allow_password_autocompletion": False,
                          "default_create_volume": True,
                          'hide_create_volume': False,
                          "image_formats": '',
                          "api_result_limit": 1000,
                          "enable_fip_topology_check": True,
                          "session_timeout": 3600,
                          "dropdown_max_items": 30,
                          "enable_consistency_groups": False,
                          "disable_instance_snapshot": False,
                          "disable_password_reveal": False,
                          "enforce_password_check": True,
                          "site_branding": "My Cloud",
                          "site_branding_link":
                              "https://mycloud.example.com/",
                          "help_url": "https://mycloud.example.com/help",
                          "create_instance_flavor_sort_key": None,
                          "create_instance_flavor_sort_reverse": False,
                          "enable_router_panel": True,
                          }
                         )

    def test_HorizonContext_can_set_disable_instance_snapshot(self):
        self.maxDiff = 900
        self.test_config.set('disable-instance-snapshot', True)
        self.assertTrue(horizon_contexts
                        .HorizonContext()()['disable_instance_snapshot'])

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

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_no_data(self, mock_format_ipv6_addr):
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar']
        self.relation_get.side_effect = self.test_relation.get
        self.context_complete.return_value = False
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_data(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'internal_host': 'bar', 'internal_port': 5001})
        self.test_config.set('use-internal-endpoints', False)
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'service_host': 'foo', 'service_port': 5000,
                          'internal_host': 'bar', 'internal_port': 5001,
                          'internal_protocol': 'http',
                          'ks_host': 'foo', 'ks_port': 5000,
                          'ks_protocol': 'http',
                          'ks_endpoint_path': 'v2.0',
                          'default_role': 'member',
                          'api_version': '2', 'service_protocol': 'http'})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_single_region(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'internal_host': 'bar', 'internal_port': 5001,
                                'region': 'regionOne'})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'service_host': 'foo', 'service_port': 5000,
                          'internal_host': 'bar', 'internal_port': 5001,
                          'internal_protocol': 'http',
                          'ks_host': 'foo', 'ks_port': 5000,
                          'ks_endpoint_path': 'v2.0',
                          'ks_protocol': 'http',
                          'default_role': 'member',
                          'api_version': '2', 'service_protocol': 'http'})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_multi_region(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'internal_host': 'bar', 'internal_port': 5001,
                                'region': 'regionOne regionTwo'})
        self.context_complete.return_value = True
        self.assertEqual(
            with_regions_sorted(horizon_contexts.IdentityServiceContext()),
            {'service_host': 'foo', 'service_port': 5000,
             'service_protocol': 'http', 'api_version': '2',
             'internal_host': 'bar', 'internal_port': 5001,
             'internal_protocol': 'http',
             'ks_host': 'foo', 'ks_port': 5000,
             'ks_protocol': 'http',
             'ks_endpoint_path': 'v2.0',
             'default_role': 'member',
             'regions': [{'endpoint': 'http://foo:5000/v2.0',
                          'title': 'regionOne'},
                         {'endpoint': 'http://foo:5000/v2.0',
                          'title': 'regionTwo'}]})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_multi_region_v3(self,
                                                    mock_format_ipv6_addr):
        mock_format_ipv6_addr.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'internal_host': 'bar', 'internal_port': 5001,
                                'region': 'regionOne regionTwo',
                                'api_version': '3',
                                'admin_domain_id': 'admindomainid'})
        self.context_complete.return_value = True
        self.assertEqual(
            with_regions_sorted(horizon_contexts.IdentityServiceContext()),
            {'admin_domain_id': 'admindomainid',
             'service_host': 'foo', 'service_port': 5000,
             'service_protocol': 'http', 'api_version': '3',
             'internal_host': 'bar', 'internal_port': 5001,
             'internal_protocol': 'http',
             'ks_host': 'foo', 'ks_port': 5000,
             'ks_protocol': 'http',
             'ks_endpoint_path': 'v3',
             'default_role': 'member',
             'regions': [{'endpoint': 'http://foo:5000/v3',
                          'title': 'regionOne'},
                         {'endpoint': 'http://foo:5000/v3',
                          'title': 'regionTwo'}]})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_api3(self, mock_format_ipv6_addr):
        mock_format_ipv6_addr.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({
            'service_host': 'foo',
            'service_port': 5000,
            'internal_host': 'bar',
            'internal_port': 5001,
            'region': 'regionOne',
            'api_version': '3',
            'admin_domain_id': 'admindomainid'})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(), {
            'service_host': 'foo',
            'service_port': 5000,
            'internal_host': 'bar',
            'internal_port': 5001,
            'internal_protocol': 'http',
            'ks_host': 'foo',
            'ks_port': 5000,
            'ks_protocol': 'http',
            'ks_endpoint_path': 'v3',
            'api_version': '3',
            'default_role': 'member',
            'admin_domain_id': 'admindomainid',
            'service_protocol': 'http'})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
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

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_default_role(self, mock_format_ipv6_addr):
        self.test_config.set('default-role', 'member')
        mock_format_ipv6_addr.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({
            'service_host': 'foo',
            'service_port': 5000,
            'internal_host': 'bar',
            'internal_port': 5001,
            'internal_protocol': 'http',
            'region': 'regionOne',
            'api_version': '3',
            'created_roles': 'Member',
            'admin_domain_id': 'admindomainid'})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(), {
            'service_host': 'foo',
            'service_port': 5000,
            'internal_host': 'bar',
            'internal_port': 5001,
            'internal_protocol': 'http',
            'ks_host': 'foo',
            'ks_port': 5000,
            'ks_protocol': 'http',
            'ks_endpoint_path': 'v3',
            'api_version': '3',
            'default_role': 'Member',
            'admin_domain_id': 'admindomainid',
            'service_protocol': 'http'})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_default_role_fallback(self,
                                                          mock_ipv6_addr):
        self.test_config.set('default-role', 'member')
        mock_ipv6_addr.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({
            'service_host': 'foo', 'service_port': 5000,
            'internal_host': 'bar', 'internal_port': 5001,
            'region': 'regionOne',
            'api_version': '3',
            'admin_domain_id': 'admindomainid'})
        self.context_complete.return_value = True
        self.assertEqual(horizon_contexts.IdentityServiceContext()(), {
            'service_host': 'foo', 'service_port': 5000,
            'internal_host': 'bar', 'internal_port': 5001,
            'internal_protocol': 'http',
            'ks_host': 'foo', 'ks_port': 5000,
            'ks_protocol': 'http',
            'ks_endpoint_path': 'v3',
            'api_version': '3',
            'default_role': 'member',
            'admin_domain_id': 'admindomainid',
            'service_protocol': 'http'})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_use_internal_endpoints(self,
                                                           mock_format_ipv6):
        mock_format_ipv6.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'internal_host': 'bar', 'internal_port': 5001,
                                'region': 'regionOne', 'api_version': '2'})
        self.test_config.set('use-internal-endpoints', True)
        self.context_complete.return_value = True
        self.maxDiff = None
        self.assertEqual(horizon_contexts.IdentityServiceContext()(),
                         {'service_host': 'foo', 'service_port': 5000,
                          'service_protocol': 'http',
                          'internal_host': 'bar', 'internal_port': 5001,
                          'internal_protocol': 'http',
                          'ks_host': 'bar', 'ks_port': 5001,
                          'ks_endpoint_path': 'v2.0',
                          'ks_protocol': 'http',
                          'api_version': '2',
                          'default_role': 'member'})

    @patch("hooks.horizon_contexts.format_ipv6_addr")
    def test_IdentityServiceContext_use_internal_endpoints_no_internal_host(
            self, mock_format_ipv6):
        mock_format_ipv6.side_effect = lambda x: x
        self.relation_ids.return_value = ['foo']
        self.related_units.return_value = ['bar', 'baz']
        self.relation_get.side_effect = self.test_relation.get
        self.test_relation.set({'service_host': 'foo', 'service_port': 5000,
                                'region': 'regionOne regionTwo',
                                'api_version': '2'})
        self.test_config.set('use-internal-endpoints', True)
        self.context_complete.return_value = True
        self.maxDiff = None
        self.assertEqual(
            with_regions_sorted(horizon_contexts.IdentityServiceContext()),
            {'service_host': 'foo', 'service_port': 5000,
             'service_protocol': 'http',
             'internal_host': None, 'internal_port': None,
             'internal_protocol': 'http',
             'ks_host': 'foo', 'ks_port': 5000,
             'ks_endpoint_path': 'v2.0',
             'ks_protocol': 'http',
             'api_version': '2',
             'default_role': 'member',
             'regions': [{'endpoint': 'http://foo:5000/v2.0',
                          'title': 'regionOne'},
                         {'endpoint': 'http://foo:5000/v2.0',
                          'title': 'regionTwo'}]})

    def test_HorizonHAProxyContext_no_cluster(self):
        self.relation_ids.return_value = []
        self.local_unit.return_value = 'openstack-dashboard/0'
        self.get_relation_ip.return_value = "10.5.0.1"
        with patch_open() as (_open, _file):
            self.assertEqual(horizon_contexts.HorizonHAProxyContext()(),
                             {'units': {'openstack-dashboard-0': '10.5.0.1'},
                              'service_ports': {'dash_insecure': [80, 70],
                                                'dash_secure': [443, 433]},
                              'prefer_ipv6': False,
                              'haproxy_expose_stats': False})
            _open.assert_called_with('/etc/default/haproxy', 'w')
            self.assertTrue(_file.write.called)
            self.get_relation_ip.assert_called_with('cluster')

    def test_HorizonHAProxyContext_clustered(self):
        self.relation_ids.return_value = ['cluster:0']
        self.related_units.return_value = [
            'openstack-dashboard/1', 'openstack-dashboard/2'
        ]
        self.relation_get.side_effect = ['10.5.0.2', '10.5.0.3']
        self.local_unit.return_value = 'openstack-dashboard/0'
        self.get_relation_ip.return_value = "10.5.0.1"
        with patch_open() as (_open, _file):
            self.assertEqual(horizon_contexts.HorizonHAProxyContext()(),
                             {'units': {'openstack-dashboard-0': '10.5.0.1',
                                        'openstack-dashboard-1': '10.5.0.2',
                                        'openstack-dashboard-2': '10.5.0.3'},
                              'service_ports': {'dash_insecure': [80, 70],
                                                'dash_secure': [443, 433]},
                              'prefer_ipv6': False,
                              'haproxy_expose_stats': False})
            _open.assert_called_with('/etc/default/haproxy', 'w')
            self.assertTrue(_file.write.called)
            self.get_relation_ip.assert_called_with('cluster')

    def test_HorizonHAProxyContext_expose_stats(self):
        self.test_config.set('haproxy-expose-stats', True)
        self.relation_ids.return_value = []
        self.local_unit.return_value = 'openstack-dashboard/0'
        self.get_relation_ip.return_value = "10.5.0.1"
        with patch_open() as (_open, _file):
            self.assertEquals(horizon_contexts.HorizonHAProxyContext()(),
                              {'units': {'openstack-dashboard-0': '10.5.0.1'},
                               'service_ports': {'dash_insecure': [80, 70],
                                                 'dash_secure': [443, 433]},
                               'prefer_ipv6': False,
                               'haproxy_expose_stats': True})
            _open.assert_called_with('/etc/default/haproxy', 'w')
            self.assertTrue(_file.write.called)

    def test_HorizonHAProxyContext_rate_limiting(self):
        limiting = True
        max_bytes_in = 100000
        limit_period = 42
        self.test_config.set('haproxy-rate-limiting-enabled', limiting)
        self.test_config.set('haproxy-max-bytes-in-rate', max_bytes_in)
        self.test_config.set('haproxy-limit-period', limit_period)
        self.relation_ids.return_value = []
        self.local_unit.return_value = 'openstack-dashboard/0'
        self.get_relation_ip.return_value = "10.5.0.1"
        with patch_open() as (_open, _file):
            self.assertEquals(horizon_contexts.HorizonHAProxyContext()(),
                              {'units': {'openstack-dashboard-0': '10.5.0.1'},
                               'service_ports': {'dash_insecure': [80, 70],
                                                 'dash_secure': [443, 433]},
                               'prefer_ipv6': False,
                               'haproxy_expose_stats': False,
                               'haproxy_rate_limiting_enabled': limiting,
                               'haproxy_max_bytes_in_rate': max_bytes_in,
                               'haproxy_limit_period': limit_period})
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

    def test_LocalSettingsContextJSON(self):
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        # One JSON and one raw relation
        self.relation_get.side_effect = [{'priority': "99",
                                          'local-settings': '"FOO = True"'},
                                         {'priority': 60,
                                          'local-settings': 'BAR = False'}]

        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin-too/0\n'
                                       'BAR = False',
                                       '# horizon-plugin/0\n'
                                       'FOO = True']})

    def test_LocalSettingsContext_unusual_priority(self):
        # First, left priority missing.
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'local-settings': 'FOO = True'},
                                         {'priority': 60,
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': []})
        # First, right priority missing.
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': 99,
                                          'local-settings': 'FOO = True'},
                                         {'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': []})
        # Left priority is None.
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': None,
                                          'local-settings': 'FOO = True'},
                                         {'priority': 60,
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin-too/0\n'
                                       'BAR = False',
                                       '# horizon-plugin/0\n'
                                       'FOO = True']})
        # Right priority is None.
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': 99,
                                          'local-settings': 'FOO = True'},
                                         {'priority': None,
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin/0\n'
                                       'FOO = True',
                                       '# horizon-plugin-too/0\n'
                                       'BAR = False']})
        # Left priority is stringy number.
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': "99",
                                          'local-settings': 'FOO = True'},
                                         {'priority': 60,
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin-too/0\n'
                                       'BAR = False',
                                       '# horizon-plugin/0\n'
                                       'FOO = True']})
        # Right priority is stringy number.
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': 99,
                                          'local-settings': 'FOO = True'},
                                         {'priority': "60",
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin-too/0\n'
                                       'BAR = False',
                                       '# horizon-plugin/0\n'
                                       'FOO = True']})
        # Both priorities are strings
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': "99",
                                          'local-settings': 'FOO = True'},
                                         {'priority': "60",
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin-too/0\n'
                                       'BAR = False',
                                       '# horizon-plugin/0\n'
                                       'FOO = True']})
        # Left priority is weired json object
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': "{'a': 1}",
                                          'local-settings': 'FOO = True'},
                                         {'priority': "60",
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin-too/0\n'
                                       'BAR = False',
                                       '# horizon-plugin/0\n'
                                       'FOO = True']})
        # right priority is weired json object
        self.relation_ids.return_value = ['plugin:0', 'plugin-too:0']
        self.related_units.side_effect = [['horizon-plugin/0'],
                                          ['horizon-plugin-too/0']]
        self.relation_get.side_effect = [{'priority': "99",
                                          'local-settings': 'FOO = True'},
                                         {'priority': "[1,2,3]",
                                          'local-settings': 'BAR = False'}]
        self.assertEqual(horizon_contexts.LocalSettingsContext()(),
                         {'settings': ['# horizon-plugin/0\n'
                                       'FOO = True',
                                       '# horizon-plugin-too/0\n'
                                       'BAR = False']})

    def test_WebSSOFIDServiceProviderContext(self):
        def relation_ids_side_effect(rname):
            return {
                'websso-fid-service-provider': [
                    'websso-fid-service-provider:0',
                    'websso-fid-service-provider:1',
                ]
            }[rname]
        self.relation_ids.side_effect = relation_ids_side_effect

        def related_units_side_effect(rid):
            return {
                'websso-fid-service-provider:0': [
                    'keystone-saml-mellon-red/0',
                    'keystone-saml-mellon-red/1',
                ],
                'websso-fid-service-provider:1': [
                    'keystone-saml-mellon-green/0',
                    'keystone-saml-mellon-green/1',
                ],
            }[rid]
        self.related_units.side_effect = related_units_side_effect

        def relation_get_side_effect(unit, rid):
            return {
                'websso-fid-service-provider:0': {
                    'keystone-saml-mellon-red/0': {
                        'ingress-address': '10.0.0.10',
                        'protocol-name': '"saml2"',
                        'idp-name': '"red"',
                        'user-facing-name': '"Red IDP"',
                    },
                    'keystone-saml-mellon-red/1': {
                        'ingress-address': '10.0.0.11',
                        'protocol-name': '"saml2"',
                        'idp-name': '"red"',
                        'user-facing-name': '"Red IDP"',
                    },
                },
                'websso-fid-service-provider:1': {
                    'keystone-saml-mellon-green/0': {
                        'ingress-address': '10.0.0.12',
                        'protocol-name': '"mapped"',
                        'idp-name': '"green"',
                        'user-facing-name': '"Green IDP"',
                    },
                    'keystone-saml-mellon-green/1': {
                        'ingress-address': '10.0.0.13',
                        'protocol-name': '"mapped"',
                        'idp-name': '"green"',
                        'user-facing-name': '"Green IDP"',
                    },
                },
            }[rid][unit]
        self.relation_get.side_effect = relation_get_side_effect

        self.assertEqual(
            horizon_contexts.WebSSOFIDServiceProviderContext()(),
            {
                'websso_data': [
                    {
                        'protocol-name': 'saml2',
                        'idp-name': 'red',
                        'user-facing-name': "Red IDP",
                    },
                    {
                        'protocol-name': 'mapped',
                        'idp-name': 'green',
                        'user-facing-name': "Green IDP",
                    },
                ]
            })

    @patch.object(horizon_contexts.policyd, 'is_policy_success_file_set')
    def test_policyd_context(self, mock_is_policy_success_file_set):
        self.test_config.set('use-policyd-override', True)

        def extract_dirs_func():
            return {'a': ['a-dir']}

        mock_is_policy_success_file_set.return_value = True
        self.assertEqual(
            horizon_contexts.PolicydContext(extract_dirs_func)(), {
                'policyd_overrides_activated': True,
                'policy_dirs': {'a': ['a-dir']},
            })
        mock_is_policy_success_file_set.return_value = False
        self.assertEqual(
            horizon_contexts.PolicydContext(extract_dirs_func)(), {
                'policyd_overrides_activated': False,
            })
        mock_is_policy_success_file_set.return_value = True
        self.test_config.set('use-policyd-override', False)
        self.assertEqual(
            horizon_contexts.PolicydContext(extract_dirs_func)(), {
                'policyd_overrides_activated': False,
            })
