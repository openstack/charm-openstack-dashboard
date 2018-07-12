#!/usr/bin/env python
#
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

import amulet
import requests
import urllib2
import time

from charmhelpers.contrib.openstack.amulet.deployment import (
    OpenStackAmuletDeployment
)

from charmhelpers.contrib.openstack.amulet.utils import (
    OpenStackAmuletUtils,
    DEBUG,
    # ERROR
)

from charmhelpers.core.decorators import (
    retry_on_exception,
)

# Use DEBUG to turn on debug logging
u = OpenStackAmuletUtils(DEBUG)


class OpenstackDashboardBasicDeployment(OpenStackAmuletDeployment):
    """Amulet tests on a basic openstack-dashboard deployment."""

    def __init__(self, series, openstack=None, source=None,
                 stable=False):
        """Deploy the entire test environment."""
        super(OpenstackDashboardBasicDeployment, self).__init__(series,
                                                                openstack,
                                                                source,
                                                                stable)
        self._add_services()
        self._add_relations()
        self._configure_services()
        self._deploy()

        u.log.info('Waiting on extended status checks...')
        exclude_services = []

        # Wait for deployment ready msgs, except exclusions
        self._auto_wait_for_status(exclude_services=exclude_services)

        self.d.sentry.wait()
        self._initialize_tests()

    def _add_services(self):
        """Add the services that we're testing, where openstack-dashboard is
        local, and the rest of the service are from lp branches that are
        compatible with the local charm (e.g. stable or next).
        """
        this_service = {'name': 'openstack-dashboard'}
        other_services = [
            {'name': 'keystone'},
            {'name': 'percona-cluster', 'constraints': {'mem': '3072M'}},
        ]
        super(OpenstackDashboardBasicDeployment, self)._add_services(
            this_service,
            other_services)

    def _add_relations(self):
        """Add all of the relations for the services."""
        relations = {
            'openstack-dashboard:identity-service':
            'keystone:identity-service',
            'openstack-dashboard:shared-db': 'percona-cluster:shared-db',
            'keystone:shared-db': 'percona-cluster:shared-db',
        }
        super(OpenstackDashboardBasicDeployment, self)._add_relations(
            relations)

    def _configure_services(self):
        """Configure all of the services."""
        horizon_config = {
            'debug': 'yes',
        }
        keystone_config = {
            'admin-password': 'openstack',
            'admin-token': 'ubuntutesting',
        }
        pxc_config = {
            'dataset-size': '25%',
            'max-connections': 1000,
            'root-password': 'ChangeMe123',
            'sst-password': 'ChangeMe123',
        }
        configs = {
            'openstack-dashboard': horizon_config,
            'percona-cluster': pxc_config,
            'keystone': keystone_config,
        }
        super(OpenstackDashboardBasicDeployment, self)._configure_services(
            configs)

    def _initialize_tests(self):
        """Perform final initialization before tests get run."""
        # Access the sentries for inspecting service units
        self.keystone_sentry = self.d.sentry['keystone'][0]
        self.openstack_dashboard_sentry = \
            self.d.sentry['openstack-dashboard'][0]

        u.log.debug('openstack release val: {}'.format(
            self._get_openstack_release()))
        u.log.debug('openstack release str: {}'.format(
            self._get_openstack_release_string()))

    # NOTE(beisner): Switch to helper once the rabbitmq test refactor lands.
    def crude_py_parse(self, file_contents, expected):
        for line in file_contents.split('\n'):
            if '=' in line:
                args = line.split('=')
                if len(args) <= 1:
                    continue
                key = args[0].strip()
                value = args[1].strip()
                if key in expected.keys():
                    if expected[key] != value:
                        msg = "Mismatch %s != %s" % (expected[key], value)
                        amulet.raise_status(amulet.FAIL, msg=msg)

    def test_050_local_settings_permissions_regression_check_lp1755027(self):
        """Assert the intended file permissions on openstack-dashboard's
           configuration file. Regression coverage for
           https://bugs.launchpad.net/bugs/1755027."""

        file_path = '/etc/openstack-dashboard/local_settings.py'
        expected_perms = '640'
        unit_sentry = self.openstack_dashboard_sentry

        # NOTE(beisner): This could be a new test helper, but it needs
        # to be a clean backport to stable with high prio, so maybe later.
        u.log.debug('Checking {} permissions...'.format(file_path))
        cmd = 'stat -c %a {}'.format(file_path)
        output, _ = u.run_cmd_unit(unit_sentry, cmd)
        assert output == expected_perms, \
            '{} perms not as expected'.format(file_path)

    def test_100_services(self):
        """Verify the expected services are running on the corresponding
           service units."""
        services = {
            self.keystone_sentry: ['keystone'],
            self.openstack_dashboard_sentry: ['apache2']
        }
        if self._get_openstack_release() >= self.trusty_liberty:
            services[self.keystone_sentry] = ['apache2']

        ret = u.validate_services_by_name(services)
        if ret:
            amulet.raise_status(amulet.FAIL, msg=ret)

    def test_200_openstack_dashboard_identity_service_relation(self):
        """Verify the openstack-dashboard to keystone identity-service
        relation data."""
        u.log.debug('Checking dashboard:keystone id relation data...')
        unit = self.openstack_dashboard_sentry
        relation = ['identity-service', 'keystone:identity-service']
        expected = {
            'private-address': u.valid_ip,
            'requested_roles': 'Member',
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('openstack-dashboard identity-service',
                                       ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_202_keystone_identity_service_relation(self):
        """Verify the keystone to openstack-dashboard identity-service
        relation data."""
        u.log.debug('Checking keystone:dashboard id relation data...')
        unit = self.keystone_sentry
        relation = ['identity-service', 'openstack-dashboard:identity-service']
        expected = {
            'auth_host': u.valid_ip,
            'auth_port': '35357',
            'auth_protocol': 'http',
            'private-address': u.valid_ip,
            'region': 'RegionOne',
            'service_host': u.valid_ip,
            'service_port': '5000',
            'service_protocol': 'http',
        }

        ret = u.validate_relation_data(unit, relation, expected)
        if ret:
            message = u.relation_error('keystone identity-service', ret)
            amulet.raise_status(amulet.FAIL, msg=message)

    def test_302_router_settings(self):
        if self._get_openstack_release() > self.trusty_icehouse:
            u.log.debug('Checking dashboard router settings...')
            unit = self.openstack_dashboard_sentry
            conf = ('/usr/share/openstack-dashboard/openstack_dashboard/'
                    'enabled/_40_router.py')
            file_contents = unit.file_contents(conf)
            expected = {
                'DISABLED': "True",
            }
            self.crude_py_parse(file_contents, expected)

    def test_400_connection(self):
        u.log.debug('Checking dashboard http response...')
        unit = self.openstack_dashboard_sentry
        dashboard_relation = unit.relation('identity-service',
                                           'keystone:identity-service')
        dashboard_ip = dashboard_relation['private-address']

        # NOTE(fnordahl) there is a eluding issue that currently makes the
        #                first request to the OpenStack Dashboard error out
        #                with 500 Internal Server Error in CI.  Temporarilly
        #                add retry logic to unwedge the gate.  This issue
        #                should be revisited and root caused properly when time
        #                allows.
        @retry_on_exception(2, base_delay=2)
        def do_request():
            response = urllib2.urlopen('http://%s/horizon' % (dashboard_ip))
            return response.read()
        html = do_request()
        if 'OpenStack Dashboard' not in html:
            msg = "Dashboard frontpage check failed"
            amulet.raise_status(amulet.FAIL, msg=msg)

    def test_401_authenticate(self):
        """Validate that authentication succeeds when client logs in through
        the OpenStack Dashboard"""

        u.log.debug('Checking authentication through dashboard...')
        unit = self.openstack_dashboard_sentry
        dashboard_relation = unit.relation('identity-service',
                                           'keystone:identity-service')
        dashboard_ip = dashboard_relation['private-address']
        url = 'http://{}/horizon/auth/login/'.format(dashboard_ip)

        api_version = None
        if self._get_openstack_release() < self.xenial_queens:
            api_version = 2

        region = u.get_keystone_endpoint(
            self.keystone_sentry.info['public-address'], api_version)

        # start session, get csrftoken
        client = requests.session()
        client.get(url)
        response = client.get(url)

        if 'csrftoken' in client.cookies:
            csrftoken = client.cookies['csrftoken']

        # build and send post request
        auth = {
            'domain': 'admin_domain',
            'username': 'admin',
            'password': 'openstack',
            'csrfmiddlewaretoken': csrftoken,
            'next': '/horizon/',
            'region': region,
        }
        if api_version == 2:
            del auth['domain']

        u.log.debug('POST data: "{}"'.format(auth))
        response = client.post(url, data=auth, headers={'Referer': url})

        if self._get_openstack_release() == self.trusty_icehouse:
            # icehouse horizon does not operate properly without the compute
            # service present in the keystone catalog.  However, checking for
            # presence of the following text is sufficient to determine whether
            # authentication succeeded or not
            expect = 'ServiceCatalogException at /admin/'
        else:
            expect = 'Projects - OpenStack Dashboard'

        if expect not in response.text:
            msg = 'FAILURE code={} text="{}"'.format(response, response.text)
            amulet.raise_status(amulet.FAIL, msg=msg)

        u.log.debug('OK')

    def test_404_connection(self):
        """Verify the apache status module gets disabled when
        hardening apache."""

        u.log.debug('Checking apache mod_status gets disabled.')
        unit = self.openstack_dashboard_sentry
        dashboard_relation = unit.relation('identity-service',
                                           'keystone:identity-service')
        dashboard_ip = dashboard_relation['private-address']

        u.log.debug('Enabling hardening for apache...')
        self.d.configure('openstack-dashboard', {'harden': 'apache'})
        time.sleep(5)  # wait for hook to run
        self.d.sentry.wait()  # wait for hook to finish

        try:
            urllib2.urlopen('http://%s/server-status' % (dashboard_ip))
        except urllib2.HTTPError as e:
            if e.code == 404:
                return
        msg = "Apache mod_status check failed."
        amulet.raise_status(amulet.FAIL, msg=msg)

    def test_900_restart_on_config_change(self):
        """Verify that the specified services are restarted when the
        config is changed."""

        sentry = self.openstack_dashboard_sentry
        juju_service = 'openstack-dashboard'

        # Expected default and alternate values
        set_default = {'use-syslog': 'False'}
        set_alternate = {'use-syslog': 'True'}

        # Services which are expected to restart upon config change,
        # and corresponding config files affected by the change
        services = {'apache2': '/etc/openstack-dashboard/local_settings.py',
                    'memcached': '/etc/openstack-dashboard/local_settings.py'}

        # Make config change, check for service restarts
        u.log.debug('Making config change on {}...'.format(juju_service))
        mtime = u.get_sentry_time(sentry)
        self.d.configure(juju_service, set_alternate)

        sleep_time = 30
        for s, conf_file in services.iteritems():
            u.log.debug("Checking that service restarted: {}".format(s))
            if not u.validate_service_config_changed(sentry, mtime, s,
                                                     conf_file,
                                                     retry_count=6,
                                                     retry_sleep_time=20,
                                                     sleep_time=sleep_time):

                self.d.configure(juju_service, set_default)
                msg = "service {} didn't restart after config change".format(s)
                amulet.raise_status(amulet.FAIL, msg=msg)
            sleep_time = 0

        self.d.configure(juju_service, set_default)

    def test_910_pause_and_resume(self):
        """The services can be paused and resumed. """
        u.log.debug('Checking pause and resume actions...')
        unit = self.d.sentry['openstack-dashboard'][0]
        unit_name = unit.info['unit_name']

        u.log.debug('Checking for active status on {}'.format(unit_name))
        assert u.status_get(unit)[0] == "active"

        u.log.debug('Running pause action on {}'.format(unit_name))
        action_id = u.run_action(unit, "pause")
        u.log.debug('Waiting on action {}'.format(action_id))
        assert u.wait_on_action(action_id), "Pause action failed."
        u.log.debug('Checking for maintenance status on {}'.format(unit_name))
        assert u.status_get(unit)[0] == "maintenance"

        u.log.debug('Running resume action on {}'.format(unit_name))
        action_id = u.run_action(unit, "resume")
        u.log.debug('Waiting on action {}'.format(action_id))
        assert u.wait_on_action(action_id), "Resume action failed."
        u.log.debug('Checking for active status on {}'.format(unit_name))
        assert u.status_get(unit)[0] == "active"
        u.log.debug('OK')
