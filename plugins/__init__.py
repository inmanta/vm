"""
    Copyright 2015 Impera

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Contact: bart@impera.io
"""

import logging, json

from impera.resources import Resource, resource, ResourceNotFoundExcpetion
from impera.agent.handler import provider, ResourceHandler
from impera.execute.util import Unknown
from impera.plugins.base import plugin

LOGGER = logging.getLogger(__name__)


def get_key_name(exporter, vm):
    return vm.public_key.name

def get_key_value(exporter, vm):
    return vm.public_key.public_key

def get_config(exporter, vm):
    """
        Create the auth url that openstack can use
    """
    if vm.iaas.iaas_config_string is None:
        raise Exception("A valid config string is required")
    return json.loads(vm.iaas.iaas_config_string)

def get_user_data(exporter, vm):
    """
        Return an empty string when the user_data value is unknown
        TODO: this is a hack
    """
    ua = None
    if isinstance(vm.user_data, Unknown):
        ua = ""
    else:
        ua = vm.user_data

    #if ua is None or ua == "":
    #    raise Exception("User data is required!")
    return ua

@resource("vm::Host", agent = "iaas.name", id_attribute = "name")
class Host(Resource):
    """
        A virtual machine managed by a hypervisor or IaaS
    """
    fields = ("name", "flavor", "image", "key_name", "user_data", "key_value", "iaas_config", "purged", "network")
    map = {"key_name" : get_key_name, "key_value" : get_key_value, "iaas_config" : get_config,
           "user_data" : get_user_data, "network": lambda _, vm: vm.network.name}

@plugin
def names(host_prefix: "string", count: "number") -> "list":
    names = []
    formatter = "%d" in host_prefix
    for i in range(1, int(count) + 1):
        if formatter:
            names.append(host_prefix % i)
        else:
            names.append(host_prefix + str(i))

    return names




