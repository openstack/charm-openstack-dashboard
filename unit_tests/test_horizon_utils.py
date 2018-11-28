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
from collections import OrderedDict
import charmhelpers.contrib.openstack.templating as templating
templating.OSConfigRenderer = MagicMock()

import hooks.horizon_utils as horizon_utils

from unit_tests.test_utils import CharmTestCase

TO_PATCH = [
    'config',
    'get_os_codename_install_source',
    'apt_update',
    'apt_upgrade',
    'apt_install',
    'configure_installation_source',
    'log',
    'cmp_pkgrevno',
    'os_release',
    'os_application_version_set',
    'reset_os_release',
]


class TestHorizonUtils(CharmTestCase):

    def setUp(self):
        super(TestHorizonUtils, self).setUp(horizon_utils, TO_PATCH)

    def test_determine_packages(self):
        horizon_utils.os_release.return_value = 'icehouse'
        self.assertEqual(
            sorted(horizon_utils.determine_packages()),
            sorted([
                'haproxy',
                'python-novaclient',
                'python-keystoneclient',
                'openstack-dashboard-ubuntu-theme',
                'python-memcache',
                'openstack-dashboard',
                'memcached']))

    def test_determine_packages_mitaka(self):
        horizon_utils.os_release.return_value = 'mitaka'
        self.assertTrue('python-pymysql' in horizon_utils.determine_packages())

    def test_determine_packages_queens(self):
        horizon_utils.os_release.return_value = 'queens'
        self.assertEqual(
            sorted(horizon_utils.determine_packages()),
            sorted(horizon_utils.BASE_PACKAGES +
                   ['python-pymysql',
                    'python-neutron-lbaas-dashboard',
                    'python-designate-dashboard',
                    'python-heat-dashboard']))

    def test_determine_packages_rocky(self):
        horizon_utils.os_release.return_value = 'rocky'
        self.assertEqual(
            sorted(horizon_utils.determine_packages()),
            sorted([p for p in horizon_utils.BASE_PACKAGES
                    if not p.startswith('python-')] +
                   horizon_utils.PY3_PACKAGES)
        )

    def test_determine_purge_packages(self):
        'Ensure no packages are identified for purge prior to rocky'
        horizon_utils.os_release.return_value = 'queens'
        self.assertEqual(horizon_utils.determine_purge_packages(), [])

    def test_determine_purge_packages_rocky(self):
        'Ensure python packages are identified for purge at rocky'
        horizon_utils.os_release.return_value = 'rocky'
        self.assertEqual(
            horizon_utils.determine_purge_packages(),
            [p for p in horizon_utils.BASE_PACKAGES
             if p.startswith('python-')] +
            ['python-django-horizon',
             'python-django-openstack-auth',
             'python-pymysql',
             'python-neutron-lbaas-dashboard',
             'python-designate-dashboard',
             'python-heat-dashboard'])

    @patch('subprocess.call')
    def test_enable_ssl(self, _call):
        horizon_utils.enable_ssl()
        _call.assert_has_calls([
            call(['a2ensite', 'default-ssl']),
            call(['a2enmod', 'ssl']),
            call(['a2enmod', 'rewrite']),
            call(['a2enmod', 'headers'])
        ])

    def test_restart_map(self):
        ex_map = OrderedDict([
            ('/etc/openstack-dashboard/local_settings.py',
             ['apache2', 'memcached']),
            ('/etc/apache2/conf.d/openstack-dashboard.conf',
             ['apache2', 'memcached']),
            ('/etc/apache2/conf-available/openstack-dashboard.conf',
             ['apache2', 'memcached']),
            ('/etc/apache2/sites-available/default-ssl',
             ['apache2', 'memcached']),
            ('/etc/apache2/sites-available/default-ssl.conf',
             ['apache2', 'memcached']),
            ('/etc/apache2/sites-available/default',
             ['apache2', 'memcached']),
            ('/etc/apache2/sites-available/000-default.conf',
             ['apache2', 'memcached']),
            ('/etc/apache2/ports.conf',
             ['apache2', 'memcached']),
            ('/etc/haproxy/haproxy.cfg',
             ['haproxy']),
            ('/usr/share/openstack-dashboard/openstack_dashboard/enabled/'
             '_40_router.py',
             ['apache2', 'memcached']),
            ('/usr/share/openstack-dashboard/openstack_dashboard/conf/'
             'keystonev3_policy.json',
             ['apache2', 'memcached']),
        ])
        self.assertEqual(horizon_utils.restart_map(), ex_map)

    @patch.object(horizon_utils, 'determine_packages')
    def test_do_openstack_upgrade(self, determine_packages):
        self.config.return_value = 'cloud:precise-havana'
        self.get_os_codename_install_source.return_value = 'havana'
        horizon_utils.os_release.return_value = 'icehouse'
        configs = MagicMock()
        determine_packages.return_value = ['testpkg']
        horizon_utils.do_openstack_upgrade(configs)
        configs.set_release.assert_called_with(openstack_release='havana')
        self.assertTrue(self.log.called)
        self.apt_update.assert_called_with(fatal=True)
        dpkg_opts = [
            '--option', 'Dpkg::Options::=--force-confnew',
            '--option', 'Dpkg::Options::=--force-confdef',
        ]
        self.apt_upgrade.assert_called_with(options=dpkg_opts,
                                            dist=True, fatal=True)
        self.apt_install.assert_called_with(['testpkg'], fatal=True)
        self.reset_os_release.assert_called()
        self.configure_installation_source.assert_called_with(
            'cloud:precise-havana'
        )

    @patch('os.path.isfile')
    @patch('os.path.isdir')
    def test_register_configs(self, _isdir, _isfile):
        _isdir.return_value = True
        _isfile.return_value = True
        self.os_release.return_value = 'havana'
        configs = horizon_utils.register_configs()
        confs = [horizon_utils.LOCAL_SETTINGS,
                 horizon_utils.HAPROXY_CONF,
                 horizon_utils.PORTS_CONF,
                 horizon_utils.APACHE_24_DEFAULT,
                 horizon_utils.APACHE_24_CONF,
                 horizon_utils.APACHE_24_SSL]
        calls = []
        for conf in confs:
            calls.append(
                call(conf, horizon_utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls)

    @patch('os.path.isdir')
    def test_register_configs_pre_install(self, _isdir):
        _isdir.return_value = False
        self.os_release.return_value = 'havana'
        configs = horizon_utils.register_configs()
        confs = [horizon_utils.LOCAL_SETTINGS,
                 horizon_utils.HAPROXY_CONF,
                 horizon_utils.PORTS_CONF,
                 horizon_utils.APACHE_24_DEFAULT,
                 horizon_utils.APACHE_24_CONF,
                 horizon_utils.APACHE_24_SSL]
        calls = []
        for conf in confs:
            calls.append(
                call(conf, horizon_utils.CONFIG_FILES[conf]['hook_contexts']))
        configs.register.assert_has_calls(calls)

    def test_assess_status(self):
        with patch.object(horizon_utils, 'assess_status_func') as asf:
            callee = MagicMock()
            asf.return_value = callee
            horizon_utils.assess_status('test-config')
            asf.assert_called_once_with('test-config')
            callee.assert_called_once_with()
            self.os_application_version_set.assert_called_with(
                horizon_utils.VERSION_PACKAGE
            )

    @patch.object(horizon_utils, 'REQUIRED_INTERFACES')
    @patch.object(horizon_utils, 'services')
    @patch.object(horizon_utils, 'make_assess_status_func')
    def test_assess_status_func(self,
                                make_assess_status_func,
                                services,
                                REQUIRED_INTERFACES):
        services.return_value = 's1'
        horizon_utils.assess_status_func('test-config')
        # ports=None whilst port checks are disabled.
        make_assess_status_func.assert_called_once_with(
            'test-config', REQUIRED_INTERFACES, services='s1', ports=None)

    def test_pause_unit_helper(self):
        with patch.object(horizon_utils, '_pause_resume_helper') as prh:
            horizon_utils.pause_unit_helper('random-config')
            prh.assert_called_once_with(horizon_utils.pause_unit,
                                        'random-config')
        with patch.object(horizon_utils, '_pause_resume_helper') as prh:
            horizon_utils.resume_unit_helper('random-config')
            prh.assert_called_once_with(horizon_utils.resume_unit,
                                        'random-config')

    @patch.object(horizon_utils, 'services')
    def test_pause_resume_helper(self, services):
        f = MagicMock()
        services.return_value = 's1'
        with patch.object(horizon_utils, 'assess_status_func') as asf:
            asf.return_value = 'assessor'
            horizon_utils._pause_resume_helper(f, 'some-config')
            asf.assert_called_once_with('some-config')
            # ports=None whilst port checks are disabled.
            f.assert_called_once_with('assessor', services='s1', ports=None)

    @patch('subprocess.check_call')
    def test_db_migration(self, mock_subprocess):
        self.cmp_pkgrevno.return_value = -1
        horizon_utils.os_release.return_value = 'mitaka'
        horizon_utils.db_migration()
        mock_subprocess.assert_called_with(
            ['python2', '/usr/share/openstack-dashboard/manage.py',
             'syncdb', '--noinput'])

    @patch('subprocess.check_call')
    def test_db_migration_bionic_and_beyond_queens(self, mock_subprocess):
        self.cmp_pkgrevno.return_value = 0
        horizon_utils.os_release.return_value = 'queens'
        horizon_utils.db_migration()
        mock_subprocess.assert_called_with(
            ['python2', '/usr/share/openstack-dashboard/manage.py',
             'migrate', '--noinput'])

    @patch('subprocess.check_call')
    def test_db_migration_bionic_and_beyond_rocky(self, mock_subprocess):
        self.cmp_pkgrevno.return_value = 0
        horizon_utils.os_release.return_value = 'rocky'
        horizon_utils.db_migration()
        mock_subprocess.assert_called_with(
            ['python3', '/usr/share/openstack-dashboard/manage.py',
             'migrate', '--noinput'])
