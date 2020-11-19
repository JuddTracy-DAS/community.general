#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
import re
import traceback

try:
    from proxmoxer import ProxmoxAPI
    HAS_PROXMOXER = True
except ImportError:
    PROXMOXER_IMP_ERR = traceback.format_exc()
    HAS_PROXMOXER = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.basic import env_fallback, missing_required_lib

# https://docs.ansible.com/ansible/latest/dev_guide/developing_modules_documenting.html#developing-modules-documenting
DOCUMENTATION = r'''
module: proxmox_kvm_info
short_description: Retrieve informations about one or more virtual machines
description:
  - Retrieve informations about virtal machines in a Proxmox Virtual Environment.
version_added: ...
author: Judd Tracy
options:
  api_host:
    description:
      - Specify the target host of the Proxmox VE cluster.
      - You can use C(PROXMOX_HOST) environment variable.
    required: true
  api_user:
    description:
      - Specify the user to authenticate with.
      - You can use C(PROXMOX_USER) environment variable.
    required: true
  api_password:
    description:
      - Specify the password to authenticate with.
      - You can use C(PROXMOX_PASSWORD) environment variable.
  name:
    description:
      - Restrict results to the virtual machine with this name.
      - Mutually exclusive with I(node) and I(vmid).
  node:
    description:
      - Restrict results to virtual machines running on this specific node a proxmox cluster.
      - Mutually exclusive with I(name) and I(vmid).
  load_sections:
    description:
      - Gather additionnal informations.
      - C(config) returns the virtual machine configuration with pending changes applied.
      - C(snapshots) returns the list of snapshots.
      - C(firewall) returns firewall configuration.
      - C(agent_network_info) returns the list of network interfaces as seen by `qemu-guest-agent`.
      - C(agent_os_info) returns OS informations as seen by `qemu-guest-agent`.
    type: 'list'
    default: ['config']
    elements: 'str'
  type:
    description:
      - Retrieve information about VMs, Templates or both.
    type: 'str'
    choices: ['all', 'vm', 'template']
    default: 'vm'
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
    type: bool
    default: 'no'
  vmid:
    description:
      - Restrict results to the virtual machine with this vmid.
      - Mutually exclusive with I(name) and I(node).
requirements:
  - proxmoxer
  - requests
seealso:
  - module: community.general.proxmox
  - module: community.general.proxmox_kvm
  - module: community.general.proxmox_template
notes:
  - The installation of qemu-guest-agent on target virtual machines is necessaryfor C(load_sections: ['agent_network_info', 'agent_os_info']) to work.
'''

EXAMPLES = r'''
- name: Retrieve data on node prx-node-01
  proxmox_kvm_info:
    api_host: proxmox.example.org
    api_user: root@pam
    api_password: super
    node: prx-node-01
  register: node_info

- name: Retrieve data on vm menhir
  proxmox_kvm_info:
    api_host: proxmox.example.org
    api_user: root@pam
    api_password: super
    name: menhir
  register: name_info

- name: Retrieve data on vmid 113
  proxmox_kvm_info:
    api_host: proxmox.example.org
    api_user: root@pam
    api_password: super
    vmid: 113
  register: vmid_info

- name: Retrieve firewall configuration on vm dolmen
  proxmox_kvm_info:
    api_host: proxmox.example.org
    api_user: root@pam
    api_password: super
    name: dolmen
    load_sections: ['firewall']
  register: firewall_info
'''

class ProxmoxAnsible:
    def __init__(self, module):
        self.proxmox_api = self._connnect(module)

    def _connnect(self, module):
        api_host = module.params['api_host']
        api_user = module.params['api_user']
        api_password = module.params['api_password']
        validate_certs = module.params['validate_certs']

        if not api_host:
            module.fail_json(msg='The api_host paramater is missing.'
                                'Please specify this paramter in the task or'
                                'use the environment variable PROXMOX_HOST')

        if not api_user:
            module.fail_json(msg='The api_user paramater is missing.'
                                'Please specify this paramter in the task or'
                                'use the environment variable PROXMOX_USER')
        
        if not api_password:
            module.fail_json(msg='The api_password paramater is missing.'
                                'Please specify this paramter in the task or'
                                'use the environment variable PROXMOX_PASSWORD')

        try:
            return ProxmoxAPI(api_host, user=api_user, password=api_password, verify_ssl=validate_certs)
        except Exception as e:
            module.fail_json(msg='%s' %e, exception=traceback.format_exc())

    def get_vms_by_cluster(self, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms]

    def get_vms_by_node(self, node, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms if vm['node'] == node]

    def get_vm_by_vmid(self, vmid, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms if vm['vmid'] == int(vmid)]

    def get_vm_by_name(self, name, **kwargs):
        vms = self.proxmox_api.cluster.resources.get(type='vm')
        return [ProxmoxVM(vm, self.proxmox_api, **kwargs) for vm in vms if vm['name'] == name]

    def find_vms(self, name=None, node=None, vmid=None, **kwargs):
        if node:
            return self.get_vms_by_node(node, **kwargs)
        elif vmid:
            return self.get_vm_by_vmid(vmid, **kwargs)
        elif name:
            return self.get_vm_by_name(name, **kwargs)

        return self.get_vms_by_cluster(**kwargs)

    def vm_present(self, module):
        pass

    def clone(self, module):
        pass


class ProxmoxVM:
    def __init__(self, vm, proxmox_api, load_sections=[]):
        self.vm = vm
        self.proxmox_api = proxmox_api
        self.proxmox_api_vm = proxmox_api.nodes(vm['node']).qemu(vm['vmid'])

        sections = [s.upper() for s in load_sections]

        if any(item in ['CONFIG','ALL'] for item in sections):
            self.vm['config'] = self.get_config()

        if any(item in ['SNAPSHOTS', 'ALL'] for item in sections):
            self.vm['snapshots'] = self.get_snapshots()
        
        if any(item in ['FIREWALL', 'ALL'] for item in sections):
            self.vm['firewall'] = self.get_firewall_settings()
        
        if any(item in ['AGENT_NETWORK_INFO', 'ALL'] for item in sections):
            if 'agent' not in self.vm:
                self.vm['agent'] = {}

            self.vm['agent']['network'] = self.get_agent_network_info()
        
        if any(item in ['AGENT_OS_INFO', 'ALL'] for item in sections):
            if 'agent' not in self.vm:
                self.vm['agent'] = {}

            self.vm['agent']['os'] = self.get_agent_os_info()

    def get_config(self):
        return self.proxmox_api_vm.config.get()

    def get_snapshots(self):
        return self.proxmox_api_vm.snapshot.get()

    def get_firewall_settings(self):
        return self.proxmox_api_vm.firewall.get()

    def get_agent_network_info(self):
        try:
            return self.proxmox_api_vm.agent.create(command='network-get-interfaces')['result']
        except:
            return { 'error': 'Error collecting network information' }

    def get_agent_os_info(self):
        try:
            return self.proxmox_api_vm.agent.create(command='get-osinfo')['result']
        except:
            return { 'error': 'Error collecting os information' }

def proxmox_argument_spec():
    return dict(
        name = dict(
            type = 'str',
            default = None,
            api_name = 'name'),
        node = dict(
            type = 'str',
            default = None,
            api_name = 'node'),
        api_host = dict(
            required = True,
            fallback = (env_fallback, ['PROXMOX_HOST'])),
        api_user = dict(
            required = True,
            fallback = (env_fallback, ['PROXMOX_USER'])),
        api_password = dict(
            no_log = True,
            fallback = (env_fallback, ['PROXMOX_PASSWORD'])),
        load_sections = dict(
            type = 'list',
            default = ['config']),
        type = dict(
            type = 'str',
            default = 'all',
            choices = ['all', 'vm', 'template']),
        validate_certs = dict(
            type = 'bool',
            default = True),
        vmid = dict(
            type = 'int',
            default = None,
            api_name = 'vmid'),
    )

def run_module():
    module_args = proxmox_argument_spec()

    module = AnsibleModule(
        argument_spec=module_args,
        mutually_exclusive=[('vmid', 'name', 'node')],
        supports_check_mode=True
    )

    result = dict(
        changed=False
    )

    if not HAS_PROXMOXER:
        module.fail_json(msg=missing_required_lib('proxmoxer'), exception=PROXMOXER_IMP_ERR)

    name = module.params['name']
    node = module.params['node']
    api_user = module.params['api_user']
    api_host = module.params['api_host']
    api_password = module.params['api_password']
    vm_type = module.params['type']
    vmid = module.params['vmid']
    validate_certs = module.params['validate_certs']
    load_sections = module.params['load_sections']

    proxmox = ProxmoxAnsible(module)
    
    vms = proxmox.find_vms(name=name, node=node, vmid=vmid, load_sections=load_sections)

    result['virtual_machines'] = [vm.vm for vm in vms]

    if module.check_mode:
        module.exit_json(**result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
