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
# import charmhelpers.contrib.openstack.templating as templating
# templating.OSConfigRenderer = MagicMock()

import hooks.horizon_utils as horizon_utils

from unit_tests.test_utils import (
    CharmTestCase,
    patch_open,
)

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
    'HorizonOSConfigRenderer',
]


class TestHorizonUtils(CharmTestCase):

    def setUp(self):
        super(TestHorizonUtils, self).setUp(horizon_utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

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
                    'python-heat-dashboard',
                    'python-neutron-fwaas-dashboard']))

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
            ('/usr/share/openstack-dashboard/openstack_dashboard/conf/'
             'cinder_policy.d/consistencygroup.yaml',
             ['apache2', 'memcached']),
        ])
        self.assertEqual(horizon_utils.restart_map(), ex_map)

    @patch.object(horizon_utils, 'determine_packages')
    def test_do_openstack_upgrade(self, determine_packages):
        self.test_config.set('openstack-origin', 'cloud:precise-havana')
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

    @patch('shutil.rmtree')
    @patch('os.path.exists')
    @patch.object(horizon_utils.policyd, 'remove_policy_success_file')
    @patch.object(horizon_utils.policyd, 'policyd_dir_for')
    @patch.object(horizon_utils.policyd,
                  'is_policyd_override_valid_on_this_release')
    def test_maybe_handle_policyd_override_config_false(
        self,
        mock_valid,
        mock_policyd_dir_for,
        mock_remove_policy_success_file,
        mock_os_path_exists,
        mock_shutils_rmtree,
    ):
        self.test_config.set('use-policyd-override', False)
        mock_valid.return_value = True
        mock_policyd_dir_for.return_value = 'a_dir'
        mock_os_path_exists.return_value = True
        horizon_utils.maybe_handle_policyd_override(
            'a_release', 'config-changed')
        mock_policyd_dir_for.assert_called_once_with('openstack-dashboard')
        mock_shutils_rmtree.assert_called_once_with('a_dir')
        mock_remove_policy_success_file.assert_called_once_with()

    @patch.object(horizon_utils.policyd, 'get_policy_resource_filename')
    @patch.object(horizon_utils.policyd, 'is_policy_success_file_set')
    @patch.object(horizon_utils.policyd,
                  'is_policyd_override_valid_on_this_release')
    def test_maybe_handle_policyd_override_config_changed_done(
        self,
        mock_valid,
        mock_is_policy_success_file_set,
        mock_get_policy_resource_filename,
    ):
        self.test_config.set('use-policyd-override', True)
        mock_valid.return_value = True
        mock_is_policy_success_file_set.return_value = True
        horizon_utils.maybe_handle_policyd_override(
            'a_release', 'config-changed')
        # test that the function bailed before getting to the resource file get
        mock_get_policy_resource_filename.assert_not_called()

    @patch.object(horizon_utils, 'service')
    @patch.object(horizon_utils, 'copy_conf_to_policyd')
    @patch.object(horizon_utils, 'blacklist_policyd_paths')
    @patch.object(horizon_utils.policyd, 'process_policy_resource_file')
    @patch.object(horizon_utils.policyd, 'get_policy_resource_filename')
    @patch.object(horizon_utils.policyd, 'is_policy_success_file_set')
    @patch.object(horizon_utils.policyd,
                  'is_policyd_override_valid_on_this_release')
    def test_maybe_handle_policyd_override_config_changed_full_run(
        self,
        mock_valid,
        mock_is_policy_success_file_set,
        mock_get_policy_resource_filename,
        mock_process_policy_resource_file,
        mock_blacklist_policyd_paths,
        mock_copy_conf_to_policyd,
        mock_service,
    ):
        self.test_config.set('use-policyd-override', True)
        mock_valid.return_value = True
        mock_is_policy_success_file_set.return_value = False
        mock_get_policy_resource_filename.return_value = "resource-file"
        mock_blacklist_policyd_paths.return_value = ['a-path']

        # test no restart
        mock_process_policy_resource_file.return_value = False
        horizon_utils.maybe_handle_policyd_override(
            'a_release', 'config-changed')
        mock_get_policy_resource_filename.assert_called_once_with()
        mock_process_policy_resource_file.assert_called_once_with(
            'resource-file',
            'openstack-dashboard',
            blacklist_paths=['a-path'],
            preserve_topdir=True,
            preprocess_filename=horizon_utils.policyd_preprocess_name,
            user='horizon',
            group='horizon')
        mock_copy_conf_to_policyd.assert_called_once_with()
        mock_service.assert_not_called()

        # test with restart
        mock_process_policy_resource_file.return_value = True
        horizon_utils.maybe_handle_policyd_override(
            'a_release', 'config-changed')
        mock_service.assert_has_calls([call('stop', 'apache2'),
                                       call('start', 'apache2')])

    @patch.object(horizon_utils, 'DASHBOARD_PKG_DIR', new='/some/dir')
    @patch('os.walk')
    @patch.object(horizon_utils.policyd, 'policyd_dir_for')
    def test_blacklist_policyd_paths(self, mock_policyd_dir_for, mock_os_walk):
        mock_policyd_dir_for.return_value = '/etc'
        # Note '/some/dir' below has to match the patch on DASHBOAD_PKG_DIR
        # above.
        mock_os_walk.return_value = [
            ('/some/dir/conf', ['a-dir'], ['file1']),
            ('/some/dir/conf/a-dir', [], ['file2'])]
        paths = horizon_utils.blacklist_policyd_paths()
        mock_policyd_dir_for.assert_called_once_with('openstack-dashboard')
        self.assertEqual(paths, ['/etc/file1', '/etc/a-dir/file2'])

    @patch.object(horizon_utils, 'DASHBOARD_PKG_DIR', new='/some/dir')
    @patch.object(horizon_utils, 'mkdir')
    @patch.object(horizon_utils, 'write_file')
    @patch('os.path.exists')
    @patch('os.walk')
    @patch.object(horizon_utils.policyd, 'policyd_dir_for')
    def test_copy_conf_to_policyd(
        self,
        mock_policyd_dir_for,
        mock_os_walk,
        mock_os_path_exists,
        mock_write_file,
        mock_mkdir,
    ):
        mock_policyd_dir_for.return_value = '/etc'
        # Note '/some/dir' below has to match the patch on DASHBOAD_PKG_DIR
        # above.
        mock_os_walk.return_value = [
            ('/some/dir/conf', ['a-dir'], ['file1']),
            ('/some/dir/conf/a-dir', [], ['file2'])]
        mock_os_path_exists.return_value = False

        with patch_open() as (_open, _file):
            _file.read.side_effect = ['content1', 'content2']
            horizon_utils.copy_conf_to_policyd()
            mock_mkdir.assert_called_once_with(
                '/etc/a-dir', owner='horizon', group='horizon', perms=0o775)
            _open.assert_has_calls([
                call('/some/dir/conf/file1', 'r'),
                call('/some/dir/conf/a-dir/file2', 'r')])
            mock_write_file.assert_has_calls([
                call('/etc/file1', 'content1', 'horizon', 'horizon'),
                call('/etc/a-dir/file2', 'content2', 'horizon', 'horizon')])

    @patch.object(horizon_utils, 'POLICYD_HORIZON_SERVICE_TO_DIR',
                  new={'a': 'a-dir', 'b': 'b-dir', 'c': 'c-dir'})
    @patch('os.walk')
    @patch.object(horizon_utils.policyd, 'policyd_dir_for')
    def test_read_policyd_dirs(
        self,
        mock_policyd_dir_for,
        mock_os_walk,
    ):
        mock_policyd_dir_for.return_value = '/etc'
        # Note '/some/dir' below has to match the patch on DASHBOAD_PKG_DIR
        # above.
        mock_os_walk.return_value = [
            ('/some/dir/conf', ['b-dir'], ['file1']),
            ('/some/dir/conf/b-dir', [], ['file2'])]
        self.assertEqual(horizon_utils.read_policyd_dirs(), {'b': ['b-dir']})

    @patch.object(horizon_utils, 'POLICYD_HORIZON_SERVICE_TO_DIR',
                  new={'a': 'a-dir', 'b': 'b-dir', 'c': 'c-dir'})
    def test_policyd_preprocess_name(self):
        # test with no separator
        with self.assertRaises(horizon_utils.policyd.BadPolicyYamlFile):
            horizon_utils.policyd_preprocess_name("a-name")
        # test unrecognised service
        with self.assertRaises(horizon_utils.policyd.BadPolicyYamlFile):
            horizon_utils.policyd_preprocess_name("d/a-name")
        # finally check that the appropriate change is made
        self.assertEqual(horizon_utils.policyd_preprocess_name('b/name'),
                         "b-dir/name")

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
