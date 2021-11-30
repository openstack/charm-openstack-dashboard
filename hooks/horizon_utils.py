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

from collections import OrderedDict
from copy import deepcopy
import json
import os
import shutil
import subprocess
import time
import tarfile

import charmhelpers.contrib.hahelpers.cluster as ch_cluster
import charmhelpers.contrib.openstack.context as context
import charmhelpers.contrib.openstack.templating as templating
import charmhelpers.contrib.openstack.policyd as policyd

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
    DEBUG,
    ERROR,
    hook_name,
    INFO,
    log,
    related_units,
    relation_get,
    relation_ids,
    resource_get,
)
from charmhelpers.core.host import (
    cmp_pkgrevno,
    CompareHostReleases,
    lsb_release,
    mkdir,
    path_hash,
    service,
    write_file,
)
from charmhelpers.fetch import (
    apt_upgrade,
    apt_update,
    add_source,
    apt_install,
    apt_purge,
    apt_autoremove,
    filter_missing_packages,
)
import charmhelpers.core.unitdata as unitdata

import hooks.horizon_contexts as horizon_contexts

BASE_PACKAGES = [
    'haproxy',
    'memcached',
    'openstack-dashboard',
    'openstack-dashboard-ubuntu-theme',
    'python-keystoneclient',
    'python-memcache',
    'python-novaclient',
]

PY3_PACKAGES = [
    'python3-django-horizon',
    'python3-designate-dashboard',
    'python3-heat-dashboard',
    'python3-neutron-lbaas-dashboard',
    'python3-neutron-fwaas-dashboard',
    'python3-keystoneclient',
    'python3-novaclient',
    'python3-memcache',
    'python3-pymysql',
    'libapache2-mod-wsgi-py3',
]

VERSION_PACKAGE = 'openstack-dashboard'

REQUIRED_INTERFACES = {
    'identity': ['identity-service'],
}

POLICYD_HORIZON_SERVICE_TO_DIR = {
    'identity': 'keystone_policy.d',
    'compute': 'nova_policy.d',
    'volume': 'cinder_policy.d',
    'image': 'glance_policy.d',
    'network': 'neutron_policy.d',
    'orchestration': 'heat_policy.d',
}

APACHE_CONF_DIR = "/etc/apache2"
LOCAL_SETTINGS = "/etc/openstack-dashboard/local_settings.py"
DASHBOARD_CONF_DIR = "/etc/openstack-dashboard/"
DASHBOARD_PKG_DIR = "/usr/share/openstack-dashboard/openstack_dashboard"
HAPROXY_CONF = "/etc/haproxy/haproxy.cfg"
APACHE_CONF = os.path.join(APACHE_CONF_DIR, "conf.d/openstack-dashboard.conf")
APACHE_24_CONF = os.path.join(APACHE_CONF_DIR,
                              "conf-available/openstack-dashboard.conf")
PORTS_CONF = os.path.join(APACHE_CONF_DIR, "ports.conf")
APACHE_24_SSL = os.path.join(APACHE_CONF_DIR,
                             "sites-available/default-ssl.conf")
APACHE_24_DEFAULT = os.path.join(APACHE_CONF_DIR,
                                 "sites-available/000-default.conf")
APACHE_SSL = os.path.join(APACHE_CONF_DIR, "sites-available/default-ssl")
APACHE_DEFAULT = os.path.join(APACHE_CONF_DIR, "sites-available/default")
INSTALL_DIR = "/usr/share/openstack-dashboard"
ROUTER_SETTING = os.path.join(DASHBOARD_PKG_DIR, 'enabled/_40_router.py')
KEYSTONEV3_POLICY = os.path.join(DASHBOARD_PKG_DIR,
                                 'conf/keystonev3_policy.json')
CONSISTENCY_GROUP_POLICY = os.path.join(
    DASHBOARD_PKG_DIR, 'conf/cinder_policy.d/consistencygroup.yaml')
TEMPLATES = 'templates'
CUSTOM_THEME_DIR = os.path.join(DASHBOARD_PKG_DIR, "themes/custom")
LOCAL_DIR = os.path.join(DASHBOARD_PKG_DIR, 'local/local_settings.d')

CONFIG_FILES = OrderedDict([
    (LOCAL_SETTINGS, {
        'hook_contexts': [horizon_contexts.HorizonContext(),
                          horizon_contexts.IdentityServiceContext(),
                          context.SyslogContext(),
                          horizon_contexts.LocalSettingsContext(),
                          horizon_contexts.ApacheSSLContext(),
                          horizon_contexts.WebSSOFIDServiceProviderContext(),
                          horizon_contexts.PolicydContext(
                              lambda: read_policyd_dirs())],
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
    (CONSISTENCY_GROUP_POLICY, {
        'hook_contexts': [horizon_contexts.HorizonContext()],
        'services': ['apache2', 'memcached'],
    }),
])


def register_configs():
    ''' Register config files with their respective contexts. '''
    release = os_release('openstack-dashboard')
    configs = HorizonOSConfigRenderer(templates_dir=TEMPLATES,
                                      openstack_release=release)

    confs = [LOCAL_SETTINGS,
             HAPROXY_CONF,
             PORTS_CONF]

    if (CompareOpenStackReleases(release) >= 'queens' and
            CompareOpenStackReleases(release) <= 'stein'):
        configs.register(
            CONSISTENCY_GROUP_POLICY,
            CONFIG_FILES[CONSISTENCY_GROUP_POLICY]['hook_contexts'])

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

    # From Trusty on use Apache 2.4
    configs.register(APACHE_24_DEFAULT,
                     CONFIG_FILES[APACHE_24_DEFAULT]['hook_contexts'])
    configs.register(APACHE_24_CONF,
                     CONFIG_FILES[APACHE_24_CONF]['hook_contexts'])
    configs.register(APACHE_24_SSL,
                     CONFIG_FILES[APACHE_24_SSL]['hook_contexts'])

    if os.path.exists(os.path.dirname(ROUTER_SETTING)):
        configs.register(ROUTER_SETTING,
                         CONFIG_FILES[ROUTER_SETTING]['hook_contexts'])

    return configs


class HorizonOSConfigRenderer(templating.OSConfigRenderer):

    def write_all(self):
        """Write all of the config files.

        This function subclasses the parent version of the function such that
        if the hook is config-changed or upgrade-charm then it defers writing
        the LOCAL_SETTINGS file until after processing the policyd stuff.
        """
        _hook = hook_name()
        if _hook not in ('upgrade-charm.real', 'config-changed'):
            return super(HorizonOSConfigRenderer, self).write_all()
        # Otherwise, first do all the other templates
        for k in self.templates.keys():
            if k != LOCAL_SETTINGS:
                self.write(k)
        # Now do the policy overrides thing
        maybe_handle_policyd_override(os_release('openstack-dashboard'),
                                      _hook)
        # Finally, let's do the LOCAL_SETTINGS if the policyd worked.
        self.write(LOCAL_SETTINGS)


def maybe_handle_policyd_override(openstack_release, hook):
    """Handle the use-policy-override config flag and resource file.

    This function checks that policy overrides are supported on this release,
    that the config flag is enabled, and then processes the resources, copies
    the package policies to the config area, loads the override files.  In the
    case where the config flag is false, it removes the policy overrides by
    deleting the config area policys.  Note that the template for
    `local_settings.py` controls where the horizon service actually reads the
    policies from.

    Note that for the 'config-changed' hook, the function is only interested in
    whether the config value of `use-policy-override` matches the current
    status of the policy overrides success file.  If it doesn't, either the
    config area policies are removed (i.e. False) or the policy overrides file
    is processed.

    :param openstack_release: The release of OpenStack installed.
    :type openstack_release: str
    :param hook: The hook name
    :type hook: str
    """
    log("Seeing if policyd overrides need doing", level=INFO)
    if not policyd.is_policyd_override_valid_on_this_release(
            openstack_release):
        log("... policy overrides not valid on this release: {}"
            .format(openstack_release),
            level=INFO)
        return
    # if policy config is not set, then remove the entire directory
    _config = config()
    if not _config.get(policyd.POLICYD_CONFIG_NAME, False):
        _dir = policyd.policyd_dir_for('openstack-dashboard')
        if os.path.exists(_dir):
            log("... config is cleared, and removing {}".format(_dir), INFO)
            shutil.rmtree(_dir)
        else:
            log("... nothing to do", INFO)
        policyd.remove_policy_success_file()
        return
    # config-change and the policyd overrides have been performed just return
    if hook == "config-changed" and policyd.is_policy_success_file_set():
        log("... already setup, so skipping.", level=INFO)
        return
    # from now on it should succeed; if it doesn't then status line will show
    # broken.
    resource_filename = policyd.get_policy_resource_filename()
    restart = policyd.process_policy_resource_file(
        resource_filename,
        'openstack-dashboard',
        blacklist_paths=blacklist_policyd_paths(),
        preserve_topdir=True,
        preprocess_filename=policyd_preprocess_name,
        user='horizon',
        group='horizon')
    copy_conf_to_policyd()
    if restart:
        service('stop', 'apache2')
        service('start', 'apache2')
    log("Policy override processing complete.", level=INFO)


def blacklist_policyd_paths():
    """Process the .../conf directory and create a list of blacklisted paths.

    This is so that the policyd helpers don't delete the copied files from the
    .../conf directory.

    :returns: list of blacklisted paths.
    :rtype: [str]
    """
    conf_dir = os.path.join(DASHBOARD_PKG_DIR, 'conf')
    conf_parts_count = len(conf_dir.split(os.path.sep))
    policy_dir = policyd.policyd_dir_for('openstack-dashboard')
    paths = []
    for root, _, files in os.walk(conf_dir):
        # make _root relative to the conf_dir
        _root = os.path.sep.join(root.split(os.path.sep)[conf_parts_count:])
        for file in files:
            paths.append(os.path.join(policy_dir, _root, file))
    log("blacklisted paths: {}".format(", ".join(paths)), INFO)
    return paths


def copy_conf_to_policyd():
    """Walk the conf_dir and copy everything into the policy_dir.

    This is used after processing the policy.d resource file to put the package
    and templated policy files in DASHBOARD_PKG_DIR/conf/ into the
    /etc/openstack-dashboard/policy.d/
    """
    log("policyd: copy files from conf to /etc/openstack-dashboard/policy.d",
        level=INFO)
    conf_dir = os.path.join(DASHBOARD_PKG_DIR, 'conf')
    conf_parts_count = len(conf_dir.split(os.path.sep))
    policy_dir = policyd.policyd_dir_for('openstack-dashboard')
    for root, dirs, files in os.walk(conf_dir):
        # make _root relative to the conf_dir
        _root = os.path.sep.join(root.split(os.path.sep)[conf_parts_count:])
        # make any dirs necessary
        for d in dirs:
            _dir = os.path.join(policy_dir, _root, d)
            if not os.path.exists(_dir):
                mkdir(_dir, owner='horizon', group='horizon', perms=0o775)
        # now copy the files.
        for f in files:
            source = os.path.join(conf_dir, _root, f)
            dest = os.path.join(policy_dir, _root, f)
            with open(source, 'r') as fh:
                content = fh.read()
            write_file(dest, content, 'horizon', 'horizon')
    log("...done.", level=INFO)


def read_policyd_dirs():
    """Return a mapping of policy type to directory name.

    This returns a subset of:

        {
            'identity': ['keystone_policy.d'],
            'compute': ['nova_policy.d'],
            'volume': ['cinder_policy.d'],
            'image': ['glance_policy.d'],
            'network': ['neutron_policy.d'],
        }

    depending on what is actually set in the policy directory that has
    been written.

    :returns: mapping of type to policyd dir name.
    :rtype: Dict[str, List[str]]
    """
    policy_dir = policyd.policyd_dir_for('openstack-dashboard')
    try:
        _, dirs, _ = list(os.walk(policy_dir))[0]
        return {k: [v] for k, v in POLICYD_HORIZON_SERVICE_TO_DIR.items()
                if v in dirs}
    except IndexError:
        # The directory doesn't exist to return an empty dictionary
        return {}
    except Exception:
        # Something else went wrong; log it but don't fail.
        log("read_policyd_dirs went wrong -- need to fix this!!", ERROR)
        import traceback
        log(traceback.format_exc(), ERROR)
        return {}


def policyd_preprocess_name(name):
    """Try to preprocess the name supplied to the one horizon expects.

    This takes a name of the form "compute/file01.yaml" and converts it to
    "nova_policy.d/file01.yaml" to match the expectations of the service.

    It raises policyd's BadPolicyYamlFile exception if the file can't be
    converted and should be skipped.

    :param name: The name to convert
    :type name: AnyStr
    :raises: charmhelpers.contrib.openstack.policyd.BadPolicyYamlFile
    :returns: the converted name
    :rtype: str
    """
    if os.path.sep not in name:
        raise policyd.BadPolicyYamlFile("No prefix for section: name={}"
                                        .format(name))
    horizon_service, name = os.path.split(name)
    try:
        policy_dir = POLICYD_HORIZON_SERVICE_TO_DIR[horizon_service]
        name = os.path.join(policy_dir, name)
    except KeyError:
        log("horizon override service {} from {} not recognised, so ignoring"
            .format(horizon_service, name),
            level=DEBUG)
        raise policyd.BadPolicyYamlFile("Bad prefix : {}"
                                        .format(horizon_service))
    return name


def restart_map():
    '''
    Determine the correct resource map to be passed to
    charmhelpers.core.restart_on_change() based on the services configured.

    :returns: dict: A dictionary mapping config file to lists of services
                    that should be restarted when file changes.
    '''
    _map = []
    for f, ctxt in CONFIG_FILES.items():
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
    packages = deepcopy(BASE_PACKAGES)
    release = CompareOpenStackReleases(os_release('openstack-dashboard'))
    # Really should be handled as a dep in the openstack-dashboard package
    if release >= 'mitaka':
        packages.append('python-pymysql')
    if release >= 'ocata' and release < 'rocky':
        packages.append('python-neutron-lbaas-dashboard')
    if release >= 'queens':
        packages.append('python-designate-dashboard')
        packages.append('python-heat-dashboard')
        packages.append('python-neutron-fwaas-dashboard')
    if release >= 'rocky':
        packages = [p for p in packages if not p.startswith('python-')]
        packages.extend(PY3_PACKAGES)
    if release >= 'stein':
        # NOTE(jamespage): Django in Ubuntu disco or later uses
        #                  mysqldb rather than pymysql.
        packages.append('python3-mysqldb')
    packages = set(packages)
    if release >= 'train':
        packages.remove('python3-neutron-lbaas-dashboard')
    if release >= 'victoria':
        packages.remove('python3-neutron-fwaas-dashboard')
    # NOTE(ajkavanagh) - don't reinstall packages (e.g. on upgrade) that
    # plugins have already indicated should not be installed as they clash with
    # the plugin.  Do add in any packages that the plugins want.  Note that
    # these will be [] during install, and thus only matter during upgrades.
    skip_packages = determine_purge_packages_dashboard_plugin()
    add_in_packages = determine_packages_dashboard_plugin()
    packages = (packages - set(skip_packages)) | set(add_in_packages)

    return list(packages)


def determine_packages_dashboard_plugin():
    """Determine the packages to install from the 'dashboard-plugin' relation.

    The relation defines two keys 'conflicting-packages' and 'install-packages'
    that are used by the plugin to signal to this charm which packages should
    be installed and which are conflicting.

    :returns: List of packages to install from dashboard plugins
    :rtype: List[str]
    """
    packages = []
    for rid in relation_ids("dashboard-plugin"):
        for unit in related_units(rid):
            rdata = relation_get(unit=unit, rid=rid)
            install_packages_json = rdata.get("install-packages", "[]")
            try:
                packages.extend(json.loads(install_packages_json))
            except json.JSONDecodeError as e:
                log("Error decoding json from {}/{}: on dashboard-plugin "
                    " relation - ignoring '{}' - error is:{}"
                    .format(rid, unit, install_packages_json, str(e)),
                    level=ERROR)
    return list(set(packages))


def determine_purge_packages():
    """
    Determine list of packages that where previously installed which are no
    longer needed.

    :returns: list of package names
    """
    pkgs = []
    release = CompareOpenStackReleases(os_release('openstack-dashboard'))
    if release >= 'rocky':
        pkgs = [p for p in BASE_PACKAGES if p.startswith('python-')]
        pkgs.extend([
            'python-django-horizon',
            'python-django-openstack-auth',
            'python-pymysql',
            'python-neutron-lbaas-dashboard',
            'python-designate-dashboard',
            'python-heat-dashboard',
        ])
    if release >= 'train':
        pkgs.append('python3-neutron-lbaas-dashboard')
    if release >= 'victoria':
        pkgs.append('python3-neutron-fwaas-dashboard')
    # NOTE(ajkavanagh) also ensure that associated plugins can purge on upgrade
    return list(set(pkgs)
                .union(set(determine_purge_packages_dashboard_plugin())))


def determine_purge_packages_dashboard_plugin():
    """Determine the packages to purge from the 'dashboard-plugin' relation.

    The relation defines two keys 'conflicting-packages' and 'install-packages'
    that are used by the plugin to signal to this charm which packages should
    be installed and which are conflicting.

    :returns: List of packages to purge from dashboard plugins
    :rtype: List[str]
    """
    conflict_packages = []
    for rid in relation_ids("dashboard-plugin"):
        for unit in related_units(rid):
            rdata = relation_get(unit=unit, rid=rid)
            conflicting_packages_json = rdata.get("conflicting-packages", "[]")
            try:
                conflict_packages.extend(json.loads(conflicting_packages_json))
            except json.JSONDecodeError as e:
                log("Error decoding json from {}/{}: on dashboard-plugin "
                    " relation - ignoring '{}' - error is:{}"
                    .format(rid, unit, conflicting_packages_json, str(e)),
                    level=ERROR)
    return list(set(conflict_packages))


def remove_old_packages():
    '''Purge any packages that need ot be removed.

    :returns: bool Whether packages were removed.
    '''
    installed_packages = filter_missing_packages(determine_purge_packages())
    if installed_packages:
        apt_purge(installed_packages, fatal=True)
        apt_autoremove(purge=True, fatal=True)
    return bool(installed_packages)


PLUGIN_PACKAGES_KV_KEY = "dashboard-plugin:{}:{}"


def make_dashboard_plugin_packages_kv_key(rid, runit):
    """Construct a key for the kv store for the packages from a unit.

    :param rid: The relation_id of the unit
    :type rid: str
    :param runit: The unit name of the unit
    :type runit: str
    :returns: String to use as a key to store the packages.
    :rtype: str
    """
    return PLUGIN_PACKAGES_KV_KEY.format(rid, runit)


def update_plugin_packages_in_kv(rid, runit):
    """Update the plugin packages for this unit in the kv store.

    It returns a tuple of 'install_packages' and 'purge_packages' that are
    different from that which was previously stored.

    :param rid: The relation_id of the unit
    :type rid: str
    :param runit: The unit name of the unit
    :type runit: str
    :returns: tuple of (added, removed) packages.
    :rtype: Tuple[List[Str],List[str]]
    """
    current = get_plugin_packages_from_kv(rid, runit)
    rdata = relation_get(unit=runit, rid=rid)
    install_packages_json = rdata.get("install-packages", "[]")
    install_packages = json.loads(install_packages_json)
    conflicting_packages_json = rdata.get("conflicting-packages", "[]")
    conflicting_packages = json.loads(conflicting_packages_json)
    removed = list(
        (set(current['install_packages']) - set(install_packages)) |
        (set(conflicting_packages) - set(current['conflicting_packages'])))
    added = list(
        (set(install_packages) - set(current['install_packages'])) |
        (set(current['conflicting_packages']) - set(conflicting_packages)))
    store_plugin_packages_in_kv(
        rid, runit, conflicting_packages, install_packages)
    return (added, removed)


def store_plugin_packages_in_kv(
        rid, runit, conflicting_packages, install_packages):
    """Store information from the dashboard plugin for packages

    Essentially, the charm needs to know what the charm wants installed and
    what packages conflict as if/when the package is removed, the charm has
    to be able to restore the original situation (prior to the plugin) and that
    means recording what the plugin installed so that it can be removed.

    :param rid: The relation_id of the unit
    :type rid: str
    :param runit: The unit name of the unit
    :type runit: str
    :param conflicting_packages: the packages the plugin says conflicts with
        the ones it wants to have installed.
    :type conflicting_packages: List[str]
    :param install_packages: the packages the plugin requires to operate.
    :type install_packages: List[str]
    """
    kv = unitdata.kv()
    kv.set(make_dashboard_plugin_packages_kv_key(rid, runit),
           {"conflicting_packages": conflicting_packages,
            "install_packages": install_packages})
    kv.flush()


def get_plugin_packages_from_kv(rid, runit):
    """Get package information concerning a dashboard plugin.

    Essentially, the charm needs to know what the charm wants installed and
    what packages conflict as if/when the package is removed, the charm has
    to be able to restore the original situation (prior to the plugin) and that
    means recording what the plugin installed so that it can be removed.

    :param rid: The relation_id of the unit
    :type rid: str
    :param runit: The unit name of the unit
    :type runit: str
    :returns: Dictionary of 'conflicting_packages' and 'install_packages' from
        the plugin.
    :rtype: Dict[str, List[str]]
    """
    kv = unitdata.kv()
    data = kv.get(make_dashboard_plugin_packages_kv_key(rid, runit),
                  default=None)
    if data is None:
        data = {}
    return {"conflicting_packages": data.get("conflicting_packages", []),
            "install_packages": data.get("install_packages", [])}


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

    remove_old_packages()

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
    _services, _ = ch_cluster.get_managed_services_and_ports(services(), [])
    return make_assess_status_func(
        configs, REQUIRED_INTERFACES,
        services=_services, ports=None)


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
    _services, _ = ch_cluster.get_managed_services_and_ports(services(), [])
    f(assess_status_func(configs),
      services=services(),
      ports=None)


def db_migration():
    release = CompareOpenStackReleases(os_release('openstack-dashboard'))
    if release >= 'rocky':
        python = 'python3'
        python_django = 'python3-django'
    else:
        python = 'python2'
        python_django = 'python-django'
    if cmp_pkgrevno(python_django, '1.9') >= 0:
        # syncdb was removed in django 1.9
        subcommand = 'migrate'
    else:
        subcommand = 'syncdb'
    cmd = [python, '/usr/share/openstack-dashboard/manage.py', subcommand,
           '--noinput']
    subprocess.check_call(cmd)


def check_custom_theme():
    if not config('custom-theme'):
        log('No custom theme configured, exiting')
        return
    try:
        os.mkdir(CUSTOM_THEME_DIR)
    except OSError as e:
        if e.errno == 17:
            pass  # already exists
    theme_file = resource_get('theme')
    log('Retrieved resource: {}'.format(theme_file))
    if theme_file:
        with tarfile.open(theme_file, 'r:gz') as in_file:
            in_file.extractall(CUSTOM_THEME_DIR)
    custom_settings = '{}/local_settings.py'.format(CUSTOM_THEME_DIR)
    if os.path.isfile(custom_settings):
        try:
            os.symlink(custom_settings, '{}/custom_theme.py'.format(LOCAL_DIR))
        except OSError as e:
            if e.errno == 17:
                pass  # already exists
    log('Custom theme updated: {}'.format(theme_file))
