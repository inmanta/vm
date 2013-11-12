"""
    Copyright 2013 KU Leuven Research and Development - iMinds - Distrinet

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Administrative Contact: dnet-project-office@cs.kuleuven.be
    Technical Contact: bart.vanbrabant@cs.kuleuven.be
"""

from Imp.resources import Resource, resource, ResourceNotFoundExcpetion
from Imp.agent.handler import provider, ResourceHandler
from Imp.execute.util import Unknown

import os, re, logging, json, tempfile, urllib, time

from http import client
from dateutil import parser

LOGGER = logging.getLogger(__name__)


#     # start generating
#     vms = types["vm::Host"]
# 
#     if len(vms) == 0:
#         return
# 
#     ssh_keys = {}
#     for vm in vms:
#         if vm.public_key:
#             ssh_keys[vm.public_key.name] = vm.public_key.public_key
# 
#         vm_def = {
#             "id" : "VirtualMachine[%s,hostname=%s]" % (vm.iaas.name, vm.name),
#             "hostname" : vm.name,
#             "type" : vm.flavor,
#             "image" : vm.image,
#             "public_key" : vm.public_key.name,
#             "user_data" : vm.user_data,
#             "requires" : ["SSHKey[%s,name=%s]" % (vm.iaas.name, vm.public_key.name)],
#         }
#         exporter.add_resource(vm_def)
# 
#     for key,value in ssh_keys.items():
#         exporter.add_resource({
#             "id" : "SSHKey[%s,name=%s]" % (vm.iaas.name, key),
#             "name" : key,
#             "value" : value.strip(),
#         })

def get_key_name(exporter, vm):
    return vm.public_key.name

def get_key_value(exporter, vm):
    return vm.public_key.public_key

@resource("vm::Host", agent = "iaas.name", id_attribute = "name")     
class VirtualMachine(Resource):
    """
        A virtual machine managed by a hypervisor or IaaS
    """
    fields = ("name", "flavor", "image", "key_name", "user_data", "key_value")
    map = {"key_name" : get_key_name, "key_value" : get_key_value}
    
# @resource("ssh::Key", agent = "vm.iaas.name", id_attribute = "name")
# class SSHKey(Resource):
#     """
#         An sshkey deployed to an IaaS
#     """
#     fields = ("name", "public_key")

# @resource("Tenant")
# class Tenant(Resource):
#     """
#         A tenant/project in openstack
#     """
#     fields = ("name", "description", "enabled")
# 
# @resource("User")  
# class User(Resource):
#     """
#         A user in openstack
#     """
#     fields = ("name", "email", "enabled", "tenant")

class OpenstackAPI(object):
    """
        This class implements an openstack API
    """
    def __init__(self, auth_url, tenant, username, password):
        self._auth_url = auth_url
        self._tenant = tenant
        self._username = username
        self._password = password
        
        self._auth_token = None
        self._auth_expire = 0
        
        self._services = {}
        
    def _connect(self, url):
        """
            Connect to the given url
        """
        parts = urllib.parse.urlparse(url)
        host, port = parts.netloc.split(":")
        
        conn = client.HTTPConnection(host, port)
        
        return (conn, parts.path)
        
    def _login(self):
        conn, path = self._connect(self._auth_url)
        
        
        request = {"auth" : {
                "tenantName" : self._tenant,
                "passwordCredentials" : {
                        "username" : self._username,
                        "password" : self._password
                }
        }}
        conn.request("POST", path + "/tokens", body = json.dumps(request),
            headers = {"Content-Type" : "application/json", "User-Agent" : "imp-agent"})
        res = conn.getresponse()
        
        if res.code != 200:
            raise Exception("Unable to login at Openstack using %s" % self._auth_url)
        
        data = json.loads(res.read().decode("utf-8"))
        
        conn.close()
        
        if "access" not in data:
            raise Exception("Received invalid response")
        
        if "token" not in data["access"]:
            raise Exception("No token received in respone")
        
        # extract token
        self._auth_token = data["access"]["token"]["id"]
        self._auth_expire = parser.parse(data["access"]["token"]["expires"]).timestamp()
        
        # extract service endpoints
        if "serviceCatalog" in data["access"]:
            for service in data["access"]["serviceCatalog"]:
                if len(service["endpoints"]) > 0:
                    self._services[service["type"]] = service["endpoints"][0]["publicURL"]
            
    def get_auth_token(self):
        if self._auth_token is None or self._auth_expire + 3600 > time.time():
            self._auth_token = None
            self._auth_expire = 0
            self._login()
            
        return self._auth_token
    
    def vm_list(self, name = None):
        """
            List all virtual machines
        """
        auth_token = self.get_auth_token()
        # REQ: curl -i http://dnetcloud.cs.kuleuven.be:8774/v2/5489e39dce68494286419f228d003d0c/servers/detail 
        # -X GET -H "X-Auth-Project-Id: bartvb" -H "User-Agent: python-novaclient" 
        # -H "Accept: application/json" -H "X-Auth-Token: dc2aca3c37dd4609834e17db55a03d01"
        
        if "compute" not in self._services:
            raise Exception("Compute service not available")
        
        compute_url = self._services["compute"] + "/servers/detail"
        
        conn, path = self._connect(compute_url)
        
        if name is not None:
            path += "?name=" + name 
        
        conn.request("GET", path, headers = {"Content-Type" : "application/json", 
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()
        
        if res.code != 200:
            raise Exception("Unable to retrieve server list at Openstack using %s" % compute_url)
        
        data = json.loads(res.read().decode("utf-8"))

        if "servers" not in data:
            raise Exception("Received invalid response from Openstack")
        
        servers = {}
        for server in data["servers"]:
            networks = []
            for net,l in server["addresses"].items():
                if len(l) > 0:
                    networks.append((net, l[0]["addr"]))
            
            servers[server["name"]] = {
                "id" : server["id"],
                "name" : server["name"],
                "properties" : server,
                "status" : server["status"],
                "networks" : networks,
            }
            
        return servers
        
    def get_ports(self, device_id = None):
        """
            Get information about the ports of the given device
        """
        auth_token = self.get_auth_token()
        
        if "network" not in self._services:
            raise Exception("Network service not available")
        
        port_url = self._services["network"] + "/v2.0/ports.json"
        
        if device_id is not None:
            port_url += "?device_id=" + device_id
        
        conn, path = self._connect(port_url)
        conn.request("GET", path, headers = {"Content-Type" : "application/json", 
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()
        
        if res.code != 200:
            raise Exception("Unable to retrieve port list at Openstack using %s" % port_url)
        
        data = json.loads(res.read().decode("utf-8"))

        if "ports" not in data:
            raise Exception("Invalid response")        
        
        ports = {}
        for port in data["ports"]:
            ports[port["id"]] = {
                "id" : port["device_id"],
                "admin_state_up" : port["admin_state_up"],
                "ips" : port["fixed_ips"],
                "mac" : port["mac_address"],
            }
            
        return ports
    
    def _parse_subnet(self, data):
        subnet_def= {
            "gateway_ip" : data["gateway_ip"],
            "cidr" : data["cidr"]
        }
        
        return data["id"], subnet_def
    
    def get_subnets(self, subnet_id = None):
        """
            Get all subnets or a specific subnet
        """
        auth_token = self.get_auth_token()

        if "network" not in self._services:
            raise Exception("Network service not available")
        
        if subnet_id is None:
            subnet_url = self._services["network"] + "/v2.0/subnets.json"
        else:
            subnet_url = self._services["network"] + "/v2.0/subnets/%s.json" % subnet_id
            
        conn, path = self._connect(subnet_url)
        conn.request("GET", path, headers = {"Content-Type" : "application/json", 
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()
        
        if res.code != 200:
            raise Exception("Unable to retrieve subnet list at Openstack using %s" % subnet_url)
        
        data = json.loads(res.read().decode("utf-8"))

        if "subnets" not in data and "subnet" not in data:
            raise Exception("Invalid response")
        
        subnets = {}
        
        if "subnet" in data:
            _id, s = self._parse_subnet(data["subnet"])
            subnets[_id] = s
            
        else:
            for subnet in data["subnets"]:
                _id, s = self._parse_subnet(subnet)
                
                subnets[_id] = s
                
        return subnets
    
    def get_keypairs(self):
        """
            Get the deployed keypairs
        """
        auth_token = self.get_auth_token()

        if "compute" not in self._services:
            raise Exception("Compute service not available")
        
        _url = self._services["compute"] + "/os-keypairs"
            
        conn, path = self._connect(_url)
        conn.request("GET", path, headers = {"Content-Type" : "application/json", 
                "User-Agent" : "imp-agent", "X-Auth-Token" : auth_token,
                "X-Auth-Project-Id" : self._tenant})
        res = conn.getresponse()
        
        if res.code != 200:
            raise Exception("Unable to retrieve keypair list at Openstack using %s" % _url)
        
        data = json.loads(res.read().decode("utf-8"))
        
        if "keypairs" not in data:
            raise Exception("Recevied a response without keypairs")
        
        keypairs = {}
        for keypair in data["keypairs"]:
            kp = keypair["keypair"]
            keypairs[kp["name"]] = {
                "fingerprint" : kp["fingerprint"],
                "public_key" : kp["public_key"],
            }
        
        return keypairs

@provider("vm::Host")
class VMHandler(ResourceHandler):
    """
        This class handles managing openstack resources
    """
    @classmethod
    def is_available(self, io):
        return io.file_exists("/usr/bin/nova") and io.file_exists("/usr/bin/quantum")
    
    def get_os_arguments(self, cloud_name):
        """
            Return the arguments for the nova clients
        """
        section_name = "openstack_%s" % cloud_name
        
        if section_name not in self._agent._config:
            raise Exception("No configuration parameters for %s cloud found" % cloud_name)
        
        cfg = self._agent._config
        arguments = ["--os-auth-url", cfg[section_name]["auth-url"], 
                     "--os-username", cfg[section_name]["username"], 
                     "--os-password", cfg[section_name]["password"],
                     "--os-tenant-name", cfg[section_name]["tenant"]]
        
        return arguments

    def _nova(self, cloud_name, command, parameters = [], binary = "/usr/bin/nova"):
        """
            Execute a nova command with given parameters
        """
        arguments = self.get_os_arguments(cloud_name) + [command] + parameters

        result = self._io.run(binary, arguments)
        
        if result[1] != '':
            raise Exception("An error occurred while calling nova with %s %s: %s" % (command, parameters, result[1]))
        
        output = result[0]
        
        if output == "":
            return None
        
        lines = [x for x in output.split("\n") if x[0] != "+"]
        
        table = []
        for row in [x.split("|")[1:-1] for x in lines]:
            table.append([])
            for cell in row:
                table[-1].append(cell.strip())

        header = table[0]
        table = table[1:]
        
        return header, table
        
    def check_resource(self, resource):
        """
            This method will check what the status of the give resource is on
            openstack.
        """
        LOGGER.debug("Checking state of resource %s" % resource)
        output = self._nova(resource.id.agent_name, "list", ["--name", resource.hostname])
        
        if output is None:
            return {}
        
        if output[0] != ['ID', 'Name', 'Status', 'Networks']:
            raise Exception("Nova list output has changed, please update agent.")
        
        vm_list = output[1]
        
        if len(vm_list) > 1:
            raise Exception("More than one virtual machine matches the resource %s" % resource.id)
        
        if len(vm_list) == 0:
            return {}
        
        vm = vm_list[0]
        
        networks = [x.split("=") for x in vm[3].split(", ")]
        
        show_output = self._nova(resource.id.agent_name, "show", [vm[0]])
        if show_output[0] != ['Property', 'Value']:
            raise Exception("Nova show output has changed, please update agent.")
        
        properties = {}
        for row in show_output[1]:
            properties[row[0]] = row[1]
        
        result = re.search(r"\(([0-9]+)\)", properties["flavor"])
        flavor = result.group(1)
        
        return {"id" : vm[0], "name" : vm[1], "status" : vm[2], "type" : flavor,
                "networks" : networks, "properties" : properties}
        
    def list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        LOGGER.debug("Determining changes required to resource %s" % resource.id)
        state = self.check_resource(resource)
        
        if state == {}:
            # create a new vm
            return {"name": (None, resource.name), 
                    "flavor": (None, str(resource.type)),
                    "image": (None, resource.image),
                    "public_key" : (None, resource.public_key),
                    "user_data" : (None, resource.user_data)}
            
        else:
            # we will not change or delete it
            return {}
        
    def do_changes(self, resource):
        """
            Enact the changes
        """
        LOGGER.debug("Making changes to resource %s" % resource.id)
        changes = self.list_changes(resource)
        
        if "name" in changes and changes["name"][0] is None:
            f = tempfile.NamedTemporaryFile(delete=False)
            f.write(changes["user_data"][1].encode("utf-8"))
            f.close()
            
            # create the VM
            self._nova(resource._parsed_id["hostname"], "boot", [
                        "--flavor", changes["flavor"][1], 
                        "--image", changes["image"][1],
                        "--key-name", changes["public_key"][1], 
                        "--user-data", f.name,
                        changes["name"][1]])
            
            os.unlink(f.name)
            
            return True

    def facts(self, resource_id):
        """
            Get facts about this resource
        """
        LOGGER.debug("Finding facts for %s" % resource_id)
        section_name = "openstack_" + resource_id.agent_name
        cfg = self._agent._config

        OS_api = OpenstackAPI(cfg[section_name]["auth-url"], 
                              cfg[section_name]["tenant"], 
                              cfg[section_name]["username"], 
                              cfg[section_name]["password"])
        
        all_status = OS_api.vm_list()
        
        if len(all_status) == 0:
            return {}
        
        ports = {}
        for port_id,port_data in OS_api.get_ports().items():
            port_data["port_id"] = port_id
            
            if port_data["id"] not in ports:
                ports[port_data["id"]] = []
                
            ports[port_data["id"]].append(port_data)

        facts = {}
        subnet_cache = {}
        for host, properties in all_status.items():
            host_facts = properties["properties"]
            del(properties["properties"])
            host_facts.update(properties)
            
            if properties["id"] in ports:
                rows = ports[properties["id"]][0]

                if len(ports[properties["id"]]) > 1:
                    LOGGER.warning("Facts only supports one interface per vm. Only the first interface is reported") 
                
                host_facts["mac_address"] = rows["mac"]
                host_facts["ip_address"] = rows["ips"][0]["ip_address"]
                subnet_id = rows["ips"][0]["subnet_id"]
                
                if subnet_id not in subnet_cache:
                    subnet_cache[subnet_id] = OS_api.get_subnets(subnet_id)[subnet_id]
                
                host_facts["cidr"] = subnet_cache[subnet_id]["cidr"]
                host_facts["gateway_ip"] = subnet_cache[subnet_id]["gateway_ip"]
                
                from Imp.iplib import CIDR
                o = CIDR(host_facts["cidr"])
                
                host_facts["netmask"] = str(o.nm)            
            
            
            facts[str(resource_id)] = host_facts
        
        return facts
        
@provider("ssh::Key")
class SSHKeyHandler(ResourceHandler):
    """
        This class handles managing ssh key in openstack
    """
    @classmethod
    def is_available(self, io):
        return io.file_exists("/usr/bin/nova")
    
    def get_os_arguments(self, cloud_name):
        """
            Return the arguments for the nova clients
        """
        section_name = "openstack_%s" % cloud_name
        
        if section_name not in self._agent._config:
            raise Exception("No configuration parameters for %s cloud found" % cloud_name)
        
        cfg = self._agent._config
        arguments = ["--os-auth-url", cfg[section_name]["auth-url"], 
                     "--os-username", cfg[section_name]["username"], 
                     "--os-password", cfg[section_name]["password"],
                     "--os-tenant-name", cfg[section_name]["tenant"]]
        
        return arguments

    def _nova(self, cloud_name, command, parameters = [], binary = "/usr/bin/nova"):
        """
            Execute a nova command with given parameters
        """
        arguments = self.get_os_arguments(cloud_name) + [command] + parameters
        
        result = self._io.run(binary, arguments)
        
        if result[1] != '':
            raise Exception("An error occurred while calling nova with %s %s: %s" % (command, parameters, result[1]))
        
        output = result[0]
        
        if output == "":
            return None
        
        lines = [x for x in output.split("\n") if x[0] != "+"]
        
        table = []
        for row in [x.split("|")[1:-1] for x in lines]:
            table.append([])
            for cell in row:
                table[-1].append(cell.strip())

        header = table[0]
        table = table[1:]
        
        return header, table
        
    def check_resource(self, resource):
        """
            This method will check what the status of the give resource is on
            openstack.
        """
        LOGGER.debug("Checking state of resource %s" % resource.id)
        output = self._nova(resource._parsed_id["hostname"], "keypair-list", [])
        
        if output is None:
            return {}
        
        if output[0] != ['Name', 'Fingerprint']:
            raise Exception("Nova list output has changed, please update agent.")

        table = output[1]
        
        for name, fingerprint in table:
            if name == resource.name:
                return {"name" : name, "fingerprint" : fingerprint}
        
        return {}
        
    def list_changes(self, resource):
        """
            List the changes that are required to the vm
        """
        LOGGER.debug("Determining changes required to resource %s" % resource.id)
        state = self.check_resource(resource)
        
        if "name" in state:
            return {}
        
        else:
            return {"name": (None, resource.name), 
                    "value": (None, resource.value)}
        
    def do_changes(self, resource):
        """
            Enact the changes
        """
        LOGGER.debug("Making changes to resource %s" % resource.id)
        changes = self.list_changes(resource)
        
        if len(changes) > 0:
            # write the key to a temporary file
            fd = tempfile.NamedTemporaryFile(delete = False, mode = "w+")
            fd.write(changes["value"][1])
            fd.close()
            
            _output = self._nova(resource._parsed_id["hostname"], "keypair-add", 
                    ["--pub-key", fd.name, changes["name"][1]])
            
            os.remove(fd.name)
            return True
