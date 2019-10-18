Overview
========

The OpenStack Dashboard provides a Django based web interface for use by both
administrators and users of an OpenStack Cloud.

It allows you to manage Nova, Glance, Cinder and Neutron resources within the
cloud.

Usage
=====

The OpenStack Dashboard is deployed and related to keystone:

    juju deploy openstack-dashboard
    juju add-relation openstack-dashboard keystone

The dashboard will use keystone for user authentication and authorization and
to interact with the catalog of services within the cloud.

The dashboard is accessible on:

    http(s)://service_unit_address/horizon

At a minimum, the cloud must provide Glance and Nova services.

SSL configuration
=================

To fully secure your dashboard services, you can provide a SSL key and
certificate for installation and configuration.  These are provided as
base64 encoded configuration options::

    juju set openstack-dashboard ssl_key="$(base64 my.key)" \
        ssl_cert="$(base64 my.cert)"

The service will be reconfigured to use the supplied information.

HA/Clustering
=============

There are two mutually exclusive high availability options: using virtual
IP(s) or DNS. In both cases, a relationship to hacluster is required which
provides the corosync back end HA functionality.

To use virtual IP(s) the clustered nodes must be on the same subnet such that
the VIP is a valid IP on the subnet for one of the node's interfaces and each
node has an interface in said subnet. The VIP becomes a highly-available API
endpoint.

At a minimum, the config option 'vip' must be set in order to use virtual IP
HA. If multiple networks are being used, a VIP should be provided for each
network, separated by spaces. Optionally, vip_iface or vip_cidr may be
specified.

To use DNS high availability there are several prerequisites. However, DNS HA
does not require the clustered nodes to be on the same subnet.
Currently the DNS HA feature is only available for MAAS 2.0 or greater
environments. MAAS 2.0 requires Juju 2.0 or greater. The clustered nodes must
have static or "reserved" IP addresses registered in MAAS. The DNS hostname(s)
must be pre-registered in MAAS before use with DNS HA.

At a minimum, the config option 'dns-ha' must be set to true and at least one
of 'os-public-hostname', 'os-internal-hostname' or 'os-internal-hostname' must
be set in order to use DNS HA. One or more of the above hostnames may be set.

The charm will throw an exception in the following circumstances:
If neither 'vip' nor 'dns-ha' is set and the charm is related to hacluster
If both 'vip' and 'dns-ha' are set as they are mutually exclusive
If 'dns-ha' is set and none of the os-{admin,internal,public}-hostname(s) are
set

Whichever method has been used to cluster the charm the 'secret' option
should be set to ensure that the Django secret is consistent across all units.

Keystone V3
===========

If the charm is being deployed into a keystone v3 enabled environment then the
charm needs to be related to a database to store session information. This is
only supported for Mitaka or later.


Use with a Load Balancing Proxy
===============================

Instead of deploying with the hacluster charm for load balancing, its possible
to also deploy the dashboard with load balancing proxy such as HAProxy:

    juju deploy haproxy
    juju add-relation haproxy openstack-dashboard
    juju add-unit -n 2 openstack-dashboard

This option potentially provides better scale-out than using the charm in
conjunction with the hacluster charm.


Custom Theme
============
This charm supports providing a custom theme as documented in the [themes
configuration]. In order to enable this capability the configuration options
'ubuntu-theme' and 'default-theme' must both be turned off and the option
'custom-theme' turned on.

Once the option is enabled a custom theme can be provided via a juju resource.
The resource should be a .tgz file with the contents of your custom theme. If
the file 'local_settings.py' is included it will be sourced.

    juju attach-resource openstack-dashboard theme=theme.tgz

Repeating the attach-resource will update the theme and turning off the
custom-theme option will return to the default.

[themes]: https://docs.openstack.org/horizon/latest/configuration/themes.html

Policy Overrides
================

This feature allows for policy overrides using the `POLICY_DIRS` override
feature of horizon (the OpenStack dashboard project).  This is an **advanced**
feature and the policies that the OpenStack dashboard supports should be
clearly understood before trying to override, or add to, the default policies
that the dashboard uses.  The charm also has some policy defaults.  They should
also be understood before being overridden.

> **Caution**: It is possible to break the system (for tenants and other
  services) if policies are incorrectly applied to the service.

Policy overrides are YAML files that contain rules that will add to, or
override, existing policy rules in the service.  This charm owns the
`POLICY_DIRS` directory, and as such, any manual changes to it will
be overwritten on charm upgrades.

The Juju resource `policyd-override` must be a ZIP file that contains at least
one directory that corresponds with the OpenStack services that the OpenStack
dashboard has policy override support for.  These directory names correspond to
the follow service/charms:

- `compute` - the compute service provided by Nova
- `identity` - the identity service provided by Keystone
- `image` - the image service provided by Glance
- `network` - the networking service provided by Neutron
- `volume` - the volume service provided by Cinder

The files in the directory/directories must be YAML files.  Thus, to provide
overrides for the `compute` and `identity` services, the resource ZIP file
should contain something like:

    \ compute - compute-override1.yaml
    |         \ compute-override2.yaml
    |
    \ identity - identity-override1.yaml
               | identity-override2.yaml
               \ identity-override3.yaml

The names of the YAML files is not important.  The names of the directories
**is** important and must match the list above.  Any other files/directories in
the ZIP are ignored.

The resource file, say `overrides.zip`, is attached to the charm by:


    juju attach-resource keystone policyd-override=overrides.zip

The policy override is enabled in the charm using:

    juju config keystone use-policyd-override=true

When `use-policyd-override` is `True` the status line of the charm will be
prefixed with `PO:` indicating that policies have been overridden.  If the
installation of the policy override YAML files failed for any reason then the
status line will be prefixed with `PO (broken):`.  The log file for the charm
will indicate the reason.  No policy override files are installed if the `PO
(broken):` is shown.  The status line indicates that the overrides are broken,
not that the policy for the service has failed. The policy will be the defaults
for the charm and service.

Policy overrides on one service may affect the functionality of another
service. Therefore, it may be necessary to provide policy overrides for
multiple service charms to achieve a consistent set of policies across the
OpenStack system.  The charms for the other services that may need overrides
should be checked to ensure that they support overrides before proceeding.
