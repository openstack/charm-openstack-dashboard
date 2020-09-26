#!/usr/bin/env python3

import json
import os
import types
from pprint import pprint
import sys

# Running this script as root is potentially dangerous as it does an import
# of untrusted python (Horizon's local_settings.py). Given that the charm
# manages that file, it shouldn't be a huge risk, but a malicious user getting
# write access to that file is a lot riskier if we then run it as root.
if os.getuid() == 0:
    raise RuntimeError("This function SHOULD NOT RUN AS ROOT")

sys.path.append('/etc/openstack-dashboard')
os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                      "openstack_dashboard.settings")


def _(a):
    return a


import django.utils.translation as translation
translation.ugettext_lazy = _
import local_settings


def get_local_settings():
    settings = {}
    if local_settings is not None:
        keys = [
            item for item in dir(local_settings) if not item.startswith("_")]
        for key in keys:
            value = getattr(local_settings, key)
            if not isinstance(value, types.ModuleType):
                print("Saving '{}' with a '{}': '{}'".format(
                      key, type(value), value), file=sys.stderr)
                settings[key] = value
    else:
        print("local_settings doesn't exist?", file=sys.stderr)
    return settings


def format_other(*args):
    return "UNSERIALIZABLE"


def main():
    settings = get_local_settings()
    pprint(settings, sys.stderr)

    settings_json = json.dumps(settings, skipkeys=True, default=format_other)
    print(settings_json)


if __name__ == "__main__":
    sys.exit(main())
