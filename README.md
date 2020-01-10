# Overview

The OpenStack Dashboard provides a Django based web interface for use by both
administrators and users of an OpenStack Cloud.

It allows you to manage Nova, Glance, Cinder and Neutron resources within the
cloud.

# Usage

The OpenStack Dashboard is deployed and related to keystone:

    juju deploy openstack-dashboard
    juju add-relation openstack-dashboard keystone

The dashboard will use keystone for user authentication and authorization and
to interact with the catalog of services within the cloud.

The dashboard is accessible on:

    http(s)://service_unit_address/horizon

At a minimum, the cloud must provide Glance and Nova services.

## SSL configuration

To fully secure your dashboard services, you can provide a SSL key and
certificate for installation and configuration. These are provided as base64
encoded configuration options::

    juju set openstack-dashboard ssl_key="$(base64 my.key)" \
        ssl_cert="$(base64 my.cert)"

The service will be reconfigured to use the supplied information.

## HA/Clustering

There are two mutually exclusive high availability options: using virtual IP(s)
or DNS. In both cases, a relationship to hacluster is required which provides
the corosync back end HA functionality.

To use virtual IP(s) the clustered nodes must be on the same subnet such that
the VIP is a valid IP on the subnet for one of the node's interfaces and each
node has an interface in said subnet. The VIP becomes a highly-available API
endpoint.

At a minimum, the config option 'vip' must be set in order to use virtual IP
HA. If multiple networks are being used, a VIP should be provided for each
network, separated by spaces. Optionally, vip_iface or vip_cidr may be
specified.

To use DNS high availability there are several prerequisites. However, DNS HA
does not require the clustered nodes to be on the same subnet. Currently the
DNS HA feature is only available for MAAS 2.0 or greater environments. MAAS 2.0
requires Juju 2.0 or greater. The clustered nodes must have static or
"reserved" IP addresses registered in MAAS. The DNS hostname(s) must be
pre-registered in MAAS before use with DNS HA.

At a minimum, the config option 'dns-ha' must be set to true and at least one
of 'os-public-hostname', 'os-internal-hostname' or 'os-internal-hostname' must
be set in order to use DNS HA. One or more of the above hostnames may be set.

The charm will throw an exception in the following circumstances: If neither
'vip' nor 'dns-ha' is set and the charm is related to hacluster If both 'vip'
and 'dns-ha' are set as they are mutually exclusive If 'dns-ha' is set and none
of the os-{admin,internal,public}-hostname(s) are set

Whichever method has been used to cluster the charm the 'secret' option should
be set to ensure that the Django secret is consistent across all units.

## Keystone V3

If the charm is being deployed into a keystone v3 enabled environment then the
charm needs to be related to a database to store session information. This is
only supported for Mitaka or later.

## Use with a Load Balancing Proxy

Instead of deploying with the hacluster charm for load balancing, its possible
to also deploy the dashboard with load balancing proxy such as HAProxy:

    juju deploy haproxy
    juju add-relation haproxy openstack-dashboard
    juju add-unit -n 2 openstack-dashboard

This option potentially provides better scale-out than using the charm in
conjunction with the hacluster charm.

## Custom Theme

This charm supports providing a custom theme as documented in the [themes]
configuration. In order to enable this capability the configuration options
'ubuntu-theme' and 'default-theme' must both be turned off and the option
'custom-theme' turned on.

Once the option is enabled a custom theme can be provided via a juju resource.
The resource should be a .tgz file with the contents of your custom theme. If
the file 'local_settings.py' is included it will be sourced.

    juju attach-resource openstack-dashboard theme=theme.tgz

Repeating the attach-resource will update the theme and turning off the
custom-theme option will return to the default.

[themes]: https://docs.openstack.org/horizon/latest/configuration/themes.html

## Policy Overrides

Policy overrides is an **advanced** feature that allows an operator to override
the default policy of an OpenStack service. The policies that the service
supports, the defaults it implements in its code, and the defaults that a charm
may include should all be clearly understood before proceeding.

> **Caution**: It is possible to break the system (for tenants and other
  services) if policies are incorrectly applied to the service.

Policy statements are placed in a YAML file. This file (or files) is then
placed into an appropriately-name directory (or directories) and (ZIP)
compressed into a single file. This compressed file is then used as an
application resource. Finally, the override is enabled via a Boolean charm
option.

The directory names correspond to the OpenStack services that Horizon has
policy override support for:

| directory name | service   | charm                  |
|----------------|-----------|------------------------|
| `compute`      | Nova      | nova-cloud-controller  |
| `identity`     | Keystone  | keystone               |
| `image`        | Glance    | glance                 |
| `network`      | Neutron   | neutron-api            |
| `volume`       | Cinder    | cinder                 |

> **Important**: The exact same overrides must also be implemented at the
  service level using the appropriate charm. See the Policy Overrides section
  of each charm's README.

For example, to provide overrides for Nova and Keystone, the compressed file
should have a structure similar to the following (the YAML filenames are
arbitrary):

    \ compute - compute-override1.yaml
    |         \ compute-override2.yaml
    |
    \ identity - identity-override1.yaml
               | identity-override2.yaml
               \ identity-override3.yaml

Here are the essential commands:

    zip -r overrides.zip compute identity
    juju attach-resource openstack-dashboard policyd-override=overrides.zip
    juju config openstack-dashboard use-policyd-override=true

See appendix [Policy Overrides][cdg-appendix-n] in the [OpenStack Charms
Deployment Guide][cdg] for a thorough treatment of this feature.

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-openstack-dashboard].

For general charm questions refer to the OpenStack [Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[cdg-appendix-n]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-policy-overrides.html
[lp-bugs-charm-openstack-dashboard]: https://bugs.launchpad.net/charm-openstack-dashboard/+filebug
