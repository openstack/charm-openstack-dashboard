# How policy.d overrides with with the dashboard charm

This document is a development note to explain how the policy.d overrides is
implemented in the charm.

## Background

Policy overrides for most OpenStack services use the oslo.policy module in
a simple fashion where the default `/etc/<service_name>/policy.d/` directory is
used.  A YAML or JSON file is dropped into this directory and the service
(which may need to be restarted) picks up the policy overrides and applies
them.

The Horizon (OpenStack dashboard) service unfortunately operates quite
differently.  The issue is that the policy files *by default* live in the
package area of the system
(`/usr/lib/python3/dist-packages/openstack_dashboard/conf`) which are also
written by the templates.  Thus, the situation is that the packages themselves
carry policy overrides as the directory (on a `bionic-stein`) look like:

	.
	./nova_policy.json
	./neutron_policy.json
	./nova_policy.d
	./nova_policy.d/api-extensions.yaml
	./keystonev3_policy.json
	./heat_policy.json
	./glance_policy.json
	./keystone_policy.json
	./cinder_policy.json
	./cinder_policy.d
	./cinder_policy.d/consistencygroup.yaml

The `keystonev3_policy.json` is *also* written by the charm to provide the
`cloud_admin` rule:

```json
{
    "admin_required": "role:Admin",
    "cloud_admin": "rule:admin_required and domain_id:3d0ec224504f4d1b9eea4d3e643b4679",
    "service_role": "role:service",
    ...
}
```

This is produced by the template `./rocky/keystonev3_policy.json` which starts
with:

```json
{
    "admin_required": "role:Admin",
    "cloud_admin": "rule:admin_required and domain_id:{{ admin_domain_id }}",
    "service_role": "role:service",
    ....
}
```

That is, the context key `admin_domain_id` is written to the packaged area of
openstack_dashboard packages using the charm template system.

## Issues for the policy.d overrides

The key issues for the policy.d overrides are:

1. The overrides need to be able to be removed and the existing, packaged,
   policies should be cleanly restored to the packaged versions.
2. They have to be consistently applied and maintained during various hooks
   that may update the configuration and thus the templates that get written to
   the packaged area.
3. The OpenStack dashboard can only be configured to read its policy files from
   one place, and that is (by default)
   `/usr/lib/python3/dist-packages/openstack_dashboard/conf`.  But it can be
   changed using the configuration setting `POLICY_FILES_PATH` in the
   `local_settings.conf`.

The first issue is basically: the charm must be able to delete any policy
override files that have been implemented with the configuration option
`use-policyd-override` is set to `false` after previously having been set to
`true`.  This essentially means that policy overrides **can't** be written to
the package area (`/usr/lib/python3/...`) without accounting for what the
packages placed there; this is brittle, so an implementation constraint is that
the *policy override files mustn't be written to the package area*.

The second issue is that hooks may update the configuration and these have to
be reflected in the configuration files that the OpenStack dashboard service is
using.

Thirdly, the `local_settings.py` needs to have the `POLICY_FILES` setting
updated by the policy file overrides, if an override is for one of `compute`,
`identity`, `image`, `network`, and/or `volume`.

All of this means that handling policy overrides is much more complicated than
for other OpenStack charms.

## How the policy.d overrides actually work on this charm

The approach taken by the OpenStack dashboard charm is to:

1. Add sections to the `local_settings` template to (if the
   `use-policyd-override` is `true`):
  * Set the `POLICY_FILES_PATH` to `/etc/openstack-dashboard/policy.d/`
  * Set the `POLICY_DIRS` to map the `compute`, `identity`, `image`, `network`,
    and/or `volume` to paths in `/etc/horizon/policy.d/nova_policy.d`, (etc.)
    for those overrides that exist in the associated policy override ZIP
    resource file.  Note that this file *has* to have `compute`, `identity` ...
    as directories in the policy ZIP file.
2. After configs are rendered, copy the entire directory tree from
   `/usr/lib/python3/dist-packages/openstack_dashboard/conf/` to
   `/etc/openstack-dashboard/policy.d/`
3. Process the policy files in the ZIP policy overrides file and place them
   into `/etc/openstack-dashboard/policy.d/nova_policy.d`, (etc...) so that the
   overrides can come into play.
4. Ensure that `apache2` is stopped and restarted so that the policies actually
   get loaded.
5. *Any* time the configuration is re-rendered, the policies are updated.

This allows the `/etc/openstack-dashboard/policy.d/` directory to be deleted
whenever a policy override is updated or cleared, as the 'pristine' policies
will always be in the package directories.

In order to be consistent in ensuring that the `/etc/horizon/policy.d/` files
are updated, the `OSConfigRenderer` class is subclassed as
`PolicyOverridesOSConfigRenderer` to provide a wrap around the `write_all`
method that copies the directory into `/etc/horizon/policy.d/` as needed.

A *blacklist* helper is provided that essentially blacklists the files in the
`.../conf` directory, as mapped into the `.../policy.d/` directory, and this is
supplied to the helper functions in charmhelpers.  This is to ensure that any
template policy files that the charm writes is not unintentionally overriden by
an override file.  This blacklist also ensures that when the directory is
deleted, that the policies from `.../conf/` will be retained.

## Implementation issues - and how they are solved

An issue for the implementation is that the charm writes configuration files to
the `.../conf` directory, but the charm *also* needs to use the files in the
`.../conf` directory when checking whether the policy overrides are acceptable.

The issue is what goes into the `local_settings.py` file for the
`POLICY_FILES_PATH` and `POLICY_DIRS` configuration options. Both of these are
determined by whether the policy overrides are acceptable, but the charm can't
discover that until the `.../conf` templates are written and the policy
overrides resource ZIP file is analyzed. Only then can the context for
`POLICY_FILES_PATH` and `POLICY_DIRS` be determined, and finally the
`local_settings.py` file be written.

Essentially, `CONFIGS.write_all()` needs to perform the validation, which is
different from the other charms.  `CONFIGS.write_all()` needs to do all the
`CONFIGS` templates *apart* from `local_settings.py`, then do the policyd
overrides processing and then do the local_settings.
