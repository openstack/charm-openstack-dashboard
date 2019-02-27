#!/usr/bin/env python3
#
# Copyright 2019 Canonical Ltd
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

import json
import subprocess
import sys

sys.path.append('.')

import charmhelpers.contrib.openstack.audits as audits
from charmhelpers.contrib.openstack.audits import (
    openstack_security_guide,
)


# Via the openstack_security_guide above, we are running the following
# security assertions automatically:
#
# - Check-Dashboard-01 - validate-file-ownership
# - Check-Dashboard-02 - validate-file-permissions


LOCAL_SETTINGS = None


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def disallow_iframe_embed(audit_options):
    """Verify disallow iframe embed.

    Security Guide Check Name: Check-Dashboard-03

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert LOCAL_SETTINGS.get('DISALLOW_IFRAME_EMBED'), \
        "DISALLOW_IFRAME_EMBED should be set to True"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def csrf_cookie_set(audit_options):
    """Verify csrf cookie set.

    Security Guide Check Name: Check-Dashboard-04

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert LOCAL_SETTINGS.get('CSRF_COOKIE_SECURE'), \
        "CSRF_COOKIE_SECURE should be set to True"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def session_cookie_store(audit_options):
    """Verify session cookie store.

    Security Guide Check Name: Check-Dashboard-05

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert LOCAL_SETTINGS.get('SESSION_COOKIE_SECURE'), \
        "SESSION_COOKIE_SECURE should be set to True"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def session_cookie_httponly(audit_options):
    """Verify session cookie httponly.

    Security Guide Check Name: Check-Dashboard-06

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert LOCAL_SETTINGS.get('SESSION_COOKIE_HTTPONLY'), \
        "SESSION_COOKIE_HTTPONLY should be set to True"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def disable_password_autocomplete(audit_options):
    """Verify disable password autocomplete.

    Security Guide Check Name: Check-Dashboard-07

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert not LOCAL_SETTINGS.get('PASSWORD_AUTOCOMPLETE'), \
        "PASSWORD_AUTOCOMPLETE should be set to False"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),
              audits.since_openstack_release('openstack-dashboard', 'kilo'))
def disable_password_reveal(audit_options):
    """Verify disable password reveal.

    Security Guide Check Name: Check-Dashboard-08

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert LOCAL_SETTINGS.get('DISABLE_PASSWORD_REVEAL'), \
        "DISABLE_PASSWORD_REVEAL should be set to True"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def enforce_password_check(audit_options):
    """Verify enforce password check.

    Security Guide Check Name: Check-Dashboard-09

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert LOCAL_SETTINGS.get('ENFORCE_PASSWORD_CHECK'), \
        "ENFORCE_PASSWORD_CHECK should be set to True"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def password_validator_is_not_default(audit_options):
    """Verify password validator is not default.

    Security Guide Check Name: Check-Dashboard-10

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    value = LOCAL_SETTINGS.get('HORIZON_CONFIG', {}).get('password_validator')
    assert value['regex'] != '.*', \
        "A non-default password_validator should be set"


@audits.audit(audits.is_audit_type(audits.AuditType.OpenStackSecurityGuide),)
def securie_proxy_ssl_header_is_set(audit_options):
    """Verify securie proxy ssl header is set.

    Security Guide Check Name: Check-Dashboard-11

    :param audit_options: Dictionary of options for audit configuration
    :type audit_options: Dict
    :raises: AssertionError if the assertion fails.
    """
    assert LOCAL_SETTINGS.get('SECURE_PROXY_SSL_HEADER') == \
        ['HTTP_X_FORWARDED_PROTO', 'https'], \
        "SECURE_PROXY_SSL_HEADER should be set to " \
        "('HTTP_X_FORWARDED_PROTO', 'https')"


def main():
    global LOCAL_SETTINGS
    config = {

        'audit_type': audits.AuditType.OpenStackSecurityGuide,
        'files': openstack_security_guide.FILE_ASSERTIONS['ceph-mon'],
        'excludes': [
            'validate-uses-keystone',
            'validate-uses-tls-for-glance',
            'validate-uses-tls-for-keystone',
        ],
    }
    LOCAL_SETTINGS = json.loads(
        subprocess.check_output([
            'sudo', '-u', 'horizon',
            'python3', 'actions/local_settings_to_json.py'],
            stderr=sys.stderr)
    )
    return audits.action_parse_results(audits.run(config))

if __name__ == "__main__":
    sys.exit(main())
