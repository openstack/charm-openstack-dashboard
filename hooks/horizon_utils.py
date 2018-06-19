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

# vim: set ts=4:et
import horizon_contexts
import os
import subprocess
import time
from collections import OrderedDict

import charmhelpers.contrib.openstack.context as context
import charmhelpers.contrib.openstack.templating as templating

from charmhelpers.contrib.openstack.utils import (
    configure_installation_source,
    get_os_codename_install_source,
    os_release,
    pause_unit,
    resume_unit,
    make_assess_status_func,
    is_unit_paused_set,
    os_application_version_set,
    CompareOpenStackReleases,
    reset_os_release,
)
from charmhelpers.core.hookenv import (
    config,
    log
)
from charmhelpers.core.host import (
    cmp_pkgrevno,
    lsb_release,
    path_hash,
    service,
    CompareHostReleases,
)
from charmhelpers.fetch import (
    apt_upgrade,
    apt_update,
    add_source,
    apt_install
)

BASE_PACKAGES = [
    'haproxy',
    'memcached',
    'openstack-dashboard',
    'openstack-dashboard-ubuntu-theme',
    'python-keystoneclient',
    'python-memcache',
    'python-novaclient',
]

VERSION_PACKAGE = 'openstack-dashboard'

REQUIRED_INTERFACES = {
    'identity': ['identity-service'],
}

APACHE_CONF_DIR = "/etc/apache2"
LOCAL_SETTINGS = "/etc/openstack-dashboard/local_settings.py"
DASHBOARD_CONF_DIR = "/etc/openstack-dashboard/"
HAPROXY_CONF = "/etc/haproxy/haproxy.cfg"
APACHE_CONF = "%s/conf.d/openstack-dashboard.conf" % (APACHE_CONF_DIR)
APACHE_24_CONF = "%s/conf-available/openstack-dashboard.conf" \
    % (APACHE_CONF_DIR)
PORTS_CONF = "%s/ports.conf" % (APACHE_CONF_DIR)
APACHE_24_SSL = "%s/sites-available/default-ssl.conf" % (APACHE_CONF_DIR)
APACHE_24_DEFAULT = "%s/sites-available/000-default.conf" % (APACHE_CONF_DIR)
APACHE_SSL = "%s/sites-available/default-ssl" % (APACHE_CONF_DIR)
APACHE_DEFAULT = "%s/sites-available/default" % (APACHE_CONF_DIR)
INSTALL_DIR = "/usr/share/openstack-dashboard"
ROUTER_SETTING = ('/usr/share/openstack-dashboard/openstack_dashboard/enabled/'
                  '_40_router.py')
KEYSTONEV3_POLICY = ('/usr/share/openstack-dashboard/openstack_dashboard/conf/'
                     'keystonev3_policy.json')
TEMPLATES = 'templates'

CONFIG_FILES = OrderedDict([
    (LOCAL_SETTINGS, {
        'hook_contexts': [horizon_contexts.HorizonContext(),
                          horizon_contexts.IdentityServiceContext(),
                          context.SyslogContext(),
                          horizon_contexts.LocalSettingsContext(),
                          horizon_contexts.ApacheSSLContext(),
                          horizon_contexts.WebSSOFIDServiceProviderContext()],
        'services': ['apache2', 'memcached']
    }),
    (APACHE_CONF, {
        'hook_contexts': [horizon_contexts.HorizonContext(),
                          context.SyslogContext(),
                          context.WSGIWorkerConfigContext()],
        'services': ['apache2', 'memcached'],
    }),
    (APACHE_24_CONF, {
        'hook_contexts': [horizon_contexts.HorizonContext(),
                          context.SyslogContext(),
                          context.WSGIWorkerConfigContext()],
        'services': ['apache2', 'memcached'],
    }),
    (APACHE_SSL, {
        'hook_contexts': [horizon_contexts.ApacheSSLContext(),
                          horizon_contexts.ApacheContext()],
        'services': ['apache2', 'memcached'],
    }),
    (APACHE_24_SSL, {
        'hook_contexts': [horizon_contexts.ApacheSSLContext(),
                          horizon_contexts.ApacheContext()],
        'services': ['apache2', 'memcached'],
    }),
    (APACHE_DEFAULT, {
        'hook_contexts': [horizon_contexts.ApacheContext()],
        'services': ['apache2', 'memcached'],
    }),
    (APACHE_24_DEFAULT, {
        'hook_contexts': [horizon_contexts.ApacheContext()],
        'services': ['apache2', 'memcached'],
    }),
    (PORTS_CONF, {
        'hook_contexts': [horizon_contexts.ApacheContext()],
        'services': ['apache2', 'memcached'],
    }),
    (HAPROXY_CONF, {
        'hook_contexts': [
            horizon_contexts.HorizonHAProxyContext(),
            context.HAProxyContext(singlenode_mode=True,
                                   address_types=[]),
        ],
        'services': ['haproxy'],
    }),
    (ROUTER_SETTING, {
        'hook_contexts': [horizon_contexts.RouterSettingContext()],
        'services': ['apache2', 'memcached'],
    }),
    (KEYSTONEV3_POLICY, {
        'hook_contexts': [horizon_contexts.IdentityServiceContext()],
        'services': ['apache2', 'memcached'],
    }),
])


def register_configs():
    ''' Register config files with their respective contexts. '''
    release = os_release('openstack-dashboard')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)

    confs = [LOCAL_SETTINGS,
             HAPROXY_CONF,
             PORTS_CONF]

    if CompareOpenStackReleases(release) >= 'mitaka':
        configs.register(KEYSTONEV3_POLICY,
                         CONFIG_FILES[KEYSTONEV3_POLICY]['hook_contexts'])
        CONFIG_FILES[LOCAL_SETTINGS]['hook_contexts'].append(
            context.SharedDBContext(
                user=config('database-user'),
                database=config('database'),
                ssl_dir=DASHBOARD_CONF_DIR))

    for conf in confs:
        configs.register(conf, CONFIG_FILES[conf]['hook_contexts'])

    if os.path.isdir(APACHE_CONF_DIR) and cmp_pkgrevno('apache2', '2.4') >= 0:
        for conf in [APACHE_CONF, APACHE_SSL, APACHE_DEFAULT]:
            if os.path.isfile(conf):
                log('Removing old config %s' % (conf))
                os.remove(conf)
        configs.register(APACHE_24_DEFAULT,
                         CONFIG_FILES[APACHE_24_DEFAULT]['hook_contexts'])
        configs.register(APACHE_24_CONF,
                         CONFIG_FILES[APACHE_24_CONF]['hook_contexts'])
        configs.register(APACHE_24_SSL,
                         CONFIG_FILES[APACHE_24_SSL]['hook_contexts'])
    else:
        configs.register(APACHE_DEFAULT,
                         CONFIG_FILES[APACHE_DEFAULT]['hook_contexts'])
        configs.register(APACHE_CONF,
                         CONFIG_FILES[APACHE_CONF]['hook_contexts'])
        configs.register(APACHE_SSL,
                         CONFIG_FILES[APACHE_SSL]['hook_contexts'])

    if os.path.exists(os.path.dirname(ROUTER_SETTING)):
        configs.register(ROUTER_SETTING,
                         CONFIG_FILES[ROUTER_SETTING]['hook_contexts'])

    return configs


def restart_map():
    '''
    Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns: dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    '''
    _map = []
    for f, ctxt in CONFIG_FILES.iteritems():
        svcs = []
        for svc in ctxt['services']:
            svcs.append(svc)
        if svcs:
            _map.append((f, svcs))
    return OrderedDict(_map)


def services():
    ''' Returns a list of services associate with this charm '''
    _services = []
    for v in restart_map().values():
        _services = _services + v
    return list(set(_services))


def enable_ssl():
    ''' Enable SSL support in local apache2 instance '''
    subprocess.call(['a2ensite', 'default-ssl'])
    subprocess.call(['a2enmod', 'ssl'])
    subprocess.call(['a2enmod', 'rewrite'])
    subprocess.call(['a2enmod', 'headers'])


def determine_packages():
    """Determine packages to install"""
    packages = BASE_PACKAGES
    release = get_os_codename_install_source(config('openstack-origin'))
    # Really should be handled as a dep in the openstack-dashboard package
    if CompareOpenStackReleases(release) >= 'mitaka':
        packages.append('python-pymysql')
    if CompareOpenStackReleases(release) >= 'ocata':
        packages.append('python-neutron-lbaas-dashboard')
    if CompareOpenStackReleases(release) >= 'queens':
        packages.append('python-designate-dashboard')
        packages.append('python-heat-dashboard')
    return list(set(packages))


def do_openstack_upgrade(configs):
    """
    Perform an upgrade.  Takes care of upgrading packages, rewriting
    configs, database migrations and potentially any other post-upgrade
    actions.

    :param configs: The charms main OSConfigRenderer object.
    """
    new_src = config('openstack-origin')
    new_os_rel = get_os_codename_install_source(new_src)

    log('Performing OpenStack upgrade to %s.' % (new_os_rel))

    configure_installation_source(new_src)
    dpkg_opts = [
        '--option', 'Dpkg::Options::=--force-confnew',
        '--option', 'Dpkg::Options::=--force-confdef',
    ]
    apt_update(fatal=True)
    apt_upgrade(options=dpkg_opts, fatal=True, dist=True)
    reset_os_release()
    apt_install(determine_packages(), fatal=True)

    # set CONFIGS to load templates from new release
    configs.set_release(openstack_release=new_os_rel)


def setup_ipv6():
    ubuntu_rel = lsb_release()['DISTRIB_CODENAME'].lower()
    if CompareHostReleases(ubuntu_rel) < "trusty":
        raise Exception("IPv6 is not supported in the charms for Ubuntu "
                        "versions less than Trusty 14.04")

    # Need haproxy >= 1.5.3 for ipv6 so for Trusty if we are <= Kilo we need to
    # use trusty-backports otherwise we can use the UCA.
    _os_release = os_release('openstack-dashboard')
    if (ubuntu_rel == 'trusty' and
            CompareOpenStackReleases(_os_release) < 'liberty'):
        add_source('deb http://archive.ubuntu.com/ubuntu trusty-backports '
                   'main')
        apt_update()
        apt_install('haproxy/trusty-backports', fatal=True)


# [thedac] Work around apache restart Bug#1552822
# Allow for sleep time between stop and start
def restart_on_change(restart_map, stopstart=False, sleep=0):
    """Restart services based on configuration files changing

    This function is used a decorator, for example::

        @restart_on_change({
            '/etc/ceph/ceph.conf': [ 'cinder-api', 'cinder-volume' ]
            '/etc/apache/sites-enabled/*': [ 'apache2' ]
            })
        def config_changed():
            pass  # your code here

    In this example, the cinder-api and cinder-volume services
    would be restarted if /etc/ceph/ceph.conf is changed by the
    ceph_client_changed function. The apache2 service would be
    restarted if any file matching the pattern got changed, created
    or removed. Standard wildcards are supported, see documentation
    for the 'glob' module for more information.

    param: sleep    Allow for sleep time between stop and start
                    Only used when stopstart=True
    """
    def wrap(f):
        def wrapped_f(*args, **kwargs):
            if is_unit_paused_set():
                return f(*args, **kwargs)
            checksums = {path: path_hash(path) for path in restart_map}
            f(*args, **kwargs)
            restarts = []
            for path in restart_map:
                if path_hash(path) != checksums[path]:
                    restarts += restart_map[path]
            services_list = list(OrderedDict.fromkeys(restarts))
            if not stopstart:
                for service_name in services_list:
                    service('restart', service_name)
            else:
                for action in ['stop', 'start']:
                    for service_name in services_list:
                        service(action, service_name)
                        if action == 'stop' and sleep:
                            time.sleep(sleep)
        return wrapped_f
    return wrap


def assess_status(configs):
    """Assess status of current unit
    Decides what the state of the unit should be based on the current
    configuration.
    SIDE EFFECT: calls set_os_workload_status(...) which sets the workload
    status of the unit.
    Also calls status_set(...) directly if paused state isn't complete.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    assess_status_func(configs)()
    os_application_version_set(VERSION_PACKAGE)


def assess_status_func(configs):
    """Helper function to create the function that will assess_status() for
    the unit.
    Uses charmhelpers.contrib.openstack.utils.make_assess_status_func() to
    create the appropriate status function and then returns it.
    Used directly by assess_status() and also for pausing and resuming
    the unit.

    NOTE(ajkavanagh) ports are not checked due to race hazards with services
    that don't behave sychronously w.r.t their service scripts.  e.g.
    apache2.
    @param configs: a templating.OSConfigRenderer() object
    @return f() -> None : a function that assesses the unit's workload status
    """
    return make_assess_status_func(
        configs, REQUIRED_INTERFACES,
        services=services(), ports=None)


def pause_unit_helper(configs):
    """Helper function to pause a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.pause_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(pause_unit, configs)


def resume_unit_helper(configs):
    """Helper function to resume a unit, and then call assess_status(...) in
    effect, so that the status is correctly updated.
    Uses charmhelpers.contrib.openstack.utils.resume_unit() to do the work.
    @param configs: a templating.OSConfigRenderer() object
    @returns None - this function is executed for its side-effect
    """
    _pause_resume_helper(resume_unit, configs)


def _pause_resume_helper(f, configs):
    """Helper function that uses the make_assess_status_func(...) from
    charmhelpers.contrib.openstack.utils to create an assess_status(...)
    function that can be used with the pause/resume of the unit
    @param f: the function to be used with the assess_status(...) function
    @returns None - this function is executed for its side-effect
    """
    # TODO(ajkavanagh) - ports= has been left off because of the race hazard
    # that exists due to service_start()
    f(assess_status_func(configs),
      services=services(),
      ports=None)


def db_migration():
    if cmp_pkgrevno('python-django', '1.9') >= 0:
        # syncdb was removed in django 1.9
        subcommand = 'migrate'
    else:
        subcommand = 'syncdb'
    cmd = ['/usr/share/openstack-dashboard/manage.py', subcommand, '--noinput']
    subprocess.check_call(cmd)
