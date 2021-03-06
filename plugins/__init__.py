"""
    Copyright 2016 Inmanta

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Contact: code@inmanta.com
"""

import logging, json

from inmanta.resources import Resource, resource, ResourceNotFoundExcpetion
from inmanta.agent.handler import provider, ResourceHandler
from inmanta.plugins import plugin
from inmanta.execute.proxy import UnknownException


LOGGER = logging.getLogger(__name__)


def get_key_name(exporter, vm):
    return vm.public_key.name

def get_key_value(exporter, vm):
    return vm.public_key.public_key

def get_config(exporter, vm):
    """
        Create the auth url that openstack can use
    """
    try:
        if vm.iaas.iaas_config_string is None:
            raise Exception("A valid config string is required")
    except UnknownException:
        return {}
    return json.loads(vm.iaas.iaas_config_string)

def get_user_data(exporter, vm):
    """
        Return an empty string when the user_data value is unknown
        TODO: this is a hack
    """
    try:
        ua = vm.user_data
    except UnknownException:
        ua = ""
    #if ua is None or ua == "":
    #    raise Exception("User data is required!")
    return ua

@resource("vm::Host", agent = "iaas.name", id_attribute = "name")
class Host(Resource):
    """
        A virtual machine managed by a hypervisor or IaaS
    """
    fields = ("name", "flavor", "image", "key_name", "user_data", "key_value", "iaas_config",
              "purged", "network", "purge_on_delete", "extraconfig")
    map = {"key_name": get_key_name,
           "key_value": get_key_value,
           "iaas_config": get_config,
           "user_data" : get_user_data,
           "network": lambda _, vm: vm.network.name,
           "extraconfig" : lambda _,xs: "{" + ",".join(["\"%s\" : %s" % (x.name,x.content) for x in xs.extraconfig ]) + "}"}

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




