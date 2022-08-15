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

import json

from charmhelpers.core.hookenv import (
    config,
    relation_ids,
    related_units,
    relation_get,
    local_unit,
    log,
    ERROR,
    WARNING,
)
from charmhelpers.core.strutils import bool_from_string
from charmhelpers.contrib.openstack import context
from charmhelpers.contrib.openstack.context import (
    OSContextGenerator,
    context_complete
)
from charmhelpers.contrib.hahelpers.cluster import (
    https,
)
from charmhelpers.contrib.network.ip import (
    get_ipv6_addr,
    format_ipv6_addr,
    get_relation_ip,
)
import charmhelpers.contrib.openstack.policyd as policyd

from charmhelpers.core.host import pwgen

VALID_ENDPOINT_TYPES = {
    'PUBLICURL': 'publicURL',
    'INTERNALURL': 'internalURL',
    'ADMINURL': 'adminURL',
}

SSL_CERT_FILE = '/etc/apache2/ssl/horizon/cert_dashboard'
SSL_KEY_FILE = '/etc/apache2/ssl/horizon/key_dashboard'


class HorizonHAProxyContext(OSContextGenerator):
    def __call__(self):
        '''
        Horizon specific HAProxy context; haproxy is used all the time
        in the openstack dashboard charm so a single instance just
        self refers
        '''
        cluster_hosts = {}
        l_unit = local_unit().replace('/', '-')
        if config('prefer-ipv6'):
            cluster_hosts[l_unit] = get_ipv6_addr(exc_list=[config('vip')])[0]
        else:
            cluster_hosts[l_unit] = get_relation_ip('cluster')

        for rid in relation_ids('cluster'):
            for unit in related_units(rid):
                _unit = unit.replace('/', '-')
                addr = relation_get('private-address', rid=rid, unit=unit)
                cluster_hosts[_unit] = addr

        log('Ensuring haproxy enabled in /etc/default/haproxy.')
        with open('/etc/default/haproxy', 'w') as out:
            out.write('ENABLED=1\n')

        ctxt = {
            'units': cluster_hosts,
            'service_ports': {
                'dash_insecure': [80, 70],
                'dash_secure': [443, 433]
            },
            'prefer_ipv6': config('prefer-ipv6'),
            'haproxy_expose_stats': config('haproxy-expose-stats')
        }
        return ctxt


class IdentityServiceContext(OSContextGenerator):
    interfaces = ['identity-service']

    def normalize(self, endpoint_type):
        """Normalizes the endpoint type values.

        :param endpoint_type (string): the endpoint type to normalize.
        :raises: Exception if the endpoint type is not valid.
        :return (string): the normalized form of the endpoint type.
        """
        normalized_form = VALID_ENDPOINT_TYPES.get(endpoint_type.upper(), None)
        if not normalized_form:
            msg = ('Endpoint type specified %s is not a valid'
                   ' endpoint type' % endpoint_type)
            log(msg, ERROR)
            raise Exception(msg)

        return normalized_form

    def __call__(self):
        log('Generating template context for identity-service')
        ctxt = {}
        regions = set()

        for rid in relation_ids('identity-service'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                default_role = config('default-role')
                lc_default_role = config('default-role').lower()
                for role in rdata.get('created_roles', '').split(','):
                    if role.lower() == lc_default_role:
                        default_role = role
                serv_host = rdata.get('service_host')
                serv_host = format_ipv6_addr(serv_host) or serv_host
                internal_host = rdata.get('internal_host')
                internal_host = (format_ipv6_addr(internal_host)
                                 or internal_host)
                region = rdata.get('region')

                local_ctxt = {
                    'service_port': rdata.get('service_port'),
                    'service_host': serv_host,
                    'service_protocol':
                    rdata.get('service_protocol') or 'http',
                    'api_version': rdata.get('api_version', '2'),
                    'default_role': default_role
                }

                # If using keystone v3 the context is incomplete without the
                # admin domain id
                if local_ctxt['api_version'] == '3':
                    local_ctxt['ks_endpoint_path'] = 'v3'
                    if not config('default_domain'):
                        local_ctxt['admin_domain_id'] = rdata.get(
                            'admin_domain_id')
                else:
                    local_ctxt['ks_endpoint_path'] = 'v2.0'
                if not context_complete(local_ctxt):
                    continue

                # internal_* keys will be treated as optional, since the user
                # could be upgrading the openstack-dashboard charm before
                # keystone, so we add them to `local_ctxt` after calling
                # `context_complete()`.
                local_ctxt.update({
                    'internal_port': rdata.get('internal_port'),
                    'internal_host': internal_host,
                    'internal_protocol':
                    rdata.get('internal_protocol') or 'http',
                })

                # if the use configured the charm to use internal endpoints,
                # but the keystone charm didn't provide the internal_host key
                # in the relation we fallback to use the service_host.
                if config("use-internal-endpoints") and internal_host:
                    log("Using internal endpoints to configure horizon")
                    local_ctxt["ks_protocol"] = local_ctxt["internal_protocol"]
                    local_ctxt["ks_host"] = local_ctxt["internal_host"]
                    local_ctxt["ks_port"] = local_ctxt["internal_port"]
                else:
                    log("Using service host to configure horizon")
                    local_ctxt["ks_protocol"] = local_ctxt["service_protocol"]
                    local_ctxt["ks_host"] = local_ctxt["service_host"]
                    local_ctxt["ks_port"] = local_ctxt["service_port"]

                # Update the service endpoint and title for each available
                # region in order to support multi-region deployments
                if region is not None:
                    if config("use-internal-endpoints") and internal_host:
                        endpoint = (
                            "{internal_protocol}://{internal_host}"
                            ":{internal_port}/{ks_endpoint_path}").format(
                                **local_ctxt)
                    else:
                        endpoint = (
                            "{service_protocol}://{service_host}"
                            ":{service_port}/{ks_endpoint_path}").format(
                                **local_ctxt)
                    for reg in region.split():
                        regions.add((endpoint, reg))

                if len(ctxt) == 0:
                    ctxt = local_ctxt

        if len(regions) > 1:
            avail_regions = map(lambda r: {'endpoint': r[0], 'title': r[1]},
                                regions)
            ctxt['regions'] = sorted(avail_regions,
                                     key=lambda k: k['endpoint'])

        # Allow the endpoint types to be specified via a config parameter.
        # The config parameter accepts either:
        #  1. a single endpoint type to be specified, in which case the
        #     primary endpoint is configured
        #  2. a list of endpoint types, in which case the primary endpoint
        #     is taken as the first entry and the secondary endpoint is
        #     taken as the second entry. All subsequent entries are ignored.
        ep_types = config('endpoint-type')
        if ep_types:
            ep_types = [self.normalize(e) for e in ep_types.split(',')]
            ctxt['primary_endpoint'] = ep_types[0]
            if len(ep_types) > 1:
                ctxt['secondary_endpoint'] = ep_types[1]

        return ctxt


class HorizonContext(OSContextGenerator):
    def __call__(self):
        ''' Provide all configuration for Horizon '''
        ctxt = {
            'compress_offline':
                bool_from_string(config('offline-compression')),
            'debug': bool_from_string(config('debug')),
            'customization_module': config('customization-module'),
            "webroot": config('webroot') or '/',
            "ubuntu_theme": bool_from_string(config('ubuntu-theme')),
            "default_theme": config('default-theme'),
            "custom_theme": config('custom-theme'),
            "secret": config('secret').strip()
                if config('secret') else pwgen(),
            'support_profile': config('profile')
                if config('profile') in ['cisco'] else None,
            "neutron_network_dvr": config("neutron-network-dvr"),
            "neutron_network_l3ha": config("neutron-network-l3ha"),
            "neutron_network_lb": config("neutron-network-lb"),
            "neutron_network_firewall": config("neutron-network-firewall"),
            "neutron_network_vpn": config("neutron-network-vpn"),
            "cinder_backup": config("cinder-backup"),
            "allow_password_autocompletion":
                config("allow-password-autocompletion"),
            "password_retrieve": config("password-retrieve"),
            'default_domain': config('default-domain'),
            'multi_domain': False if config('default-domain') else True,
            "default_create_volume": config("default-create-volume"),
            'hide_create_volume': config('hide-create-volume'),
            'image_formats': config('image-formats'),
            'api_result_limit': config('api-result-limit') or 1000,
            'enable_fip_topology_check': config('enable-fip-topology-check'),
            'session_timeout': config('session-timeout'),
            'dropdown_max_items': config('dropdown-max-items'),
            'enable_consistency_groups': config('enable-consistency-groups'),
            'disable_instance_snapshot': bool(
                config('disable-instance-snapshot')),
            'disable_password_reveal': config('disable-password-reveal'),
            'enforce_password_check': config('enforce-password-check'),
            'site_branding': config('site-branding'),
            'site_branding_link': config('site-branding-link'),
            'help_url': config('help-url'),
            'create_instance_flavor_sort_key':
                config('create-instance-flavor-sort-key'),
            'create_instance_flavor_sort_reverse':
                config('create-instance-flavor-sort-reverse'),
            'enable_router_panel':
                config('enable-router-panel'),
        }

        return ctxt


class PolicydContext(OSContextGenerator):

    def __init__(self, policyd_extract_policy_dirs_fn):
        self.policyd_extract_policy_dirs_fn = policyd_extract_policy_dirs_fn

    def __call__(self):
        """Policyd variables for the local_settings.py configuration file.

        :returns: The context to help set vars in the localsettings.
        :rtype: Dict[str, ANY]
        """
        activated = (config('use-policyd-override') and
                     policyd.is_policy_success_file_set())

        if activated:
            return {
                'policyd_overrides_activated': activated,
                'policy_dirs': self.policyd_extract_policy_dirs_fn(),
            }
        else:
            return {
                'policyd_overrides_activated': activated
            }


class ApacheContext(OSContextGenerator):
    def __call__(self):
        ''' Grab cert and key from configuraton for SSL config '''
        ctxt = {
            'http_port': 70,
            'https_port': 433,
            'enforce_ssl': False,
            'hsts_max_age_seconds': config('hsts-max-age-seconds'),
            "custom_theme": config('custom-theme'),
        }

        if config('enforce-ssl'):
            if https():
                ctxt['enforce_ssl'] = True
            else:
                log("Enforce ssl redirect requested but ssl not configured - "
                    "skipping redirect", level=WARNING)

        return ctxt


class ApacheSSLContext(context.ApacheSSLContext):

    interfaces = ['https']
    external_ports = [443]
    service_namespace = 'horizon'

    def __call__(self):
        return super(ApacheSSLContext, self).__call__()


class RouterSettingContext(OSContextGenerator):
    def __call__(self):
        ''' Enable/Disable Router Tab on horizon '''
        ctxt = {
            'disable_router': False if config('profile') in ['cisco'] else True
        }
        return ctxt


class LocalSettingsContext(OSContextGenerator):
    def __call__(self):
        ''' Additional config stanzas to be appended to local_settings.py '''

        relations = []

        # Juju 'internal' data like egress-address is not json encoded. So only
        # try and decode the keys we know to expect.
        json_keys = [
            'local-settings',
            'priority',
            'conflicting-packages',
            'install-packages']
        for rid in relation_ids("dashboard-plugin"):
            try:
                unit = related_units(rid)[0]
            except IndexError:
                pass
            else:
                rdata = relation_get(unit=unit, rid=rid)
                if set(('local-settings', 'priority')) <= set(rdata.keys()):
                    # Classic dashboard plugins may send non-json data but
                    # reactive charms send json. Attempt to json decode the
                    # data but fallback if that fails.
                    decoded_data = {}
                    try:
                        for key in rdata.keys():
                            if key in json_keys:
                                decoded_data[key] = json.loads(rdata[key])
                            else:
                                decoded_data[key] = rdata[key]
                    except (json.decoder.JSONDecodeError, TypeError):
                        relations.append((unit, rdata))
                    else:
                        relations.append((unit, decoded_data))

        ctxt = {
            'settings': [
                '# {0}\n{1}'.format(u, rd['local-settings'])
                for u, rd in sorted(relations,
                                    key=lambda r: r[1]['priority'])]
        }
        return ctxt


class WebSSOFIDServiceProviderContext(OSContextGenerator):
    interfaces = ['websso-fid-service-provider']

    def __call__(self):
        websso_keys = ['protocol-name', 'idp-name', 'user-facing-name']

        relations = []
        for rid in relation_ids("websso-fid-service-provider"):
            try:
                # the first unit will do - the assumption is that all
                # of them should advertise the same data. This needs
                # refactoring if juju gets per-application relation data
                # support
                unit = related_units(rid)[0]
            except IndexError:
                pass
            else:
                rdata = relation_get(unit=unit, rid=rid)
                if set(rdata).issuperset(set(websso_keys)):
                    relations.append({k: json.loads(rdata[k])
                                      for k in websso_keys})
        # populate the context with data from one or more
        # service providers
        ctxt = {'websso_data': relations} if relations else {}
        return ctxt
