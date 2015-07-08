#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
module: github_key
short_description: Manage GitHub access keys.
description:
    - Creates, removes, or updates GitHub access keys.
This module has a dependency on requests.
options:
  token:
    description:
      - GitHub Access Token with permission to list and create public keys.
    required: true
  name:
    description:
      - SSH key name
    required: true
  pubkey:
    description:
      - SSH public key value. Required when state=present
    required: false
  state:
    description:
      - Whether to remove a key, ensure that it exists, or update its value.
    choices: ['present', 'absent', 'updated']
    default: 'present'

author: Robert Estelle (@erydo)
'''

EXAMPLES = '''
- name: Read SSH public key to authorize
  shell: cat /home/foo/.ssh/id_rsa.pub
  register: ssh_pub_key

- name: Authorize key with GitHub
  local_action:
    module: github_key
    name: 'Access Key for Some Machine'
    token: '{{github_access_token}}'
    pubkey: '{{ssh_pub_key.stdout}}'
'''


import sys  # noqa
import json

HAS_REQUESTS = False
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    pass


API_BASE = 'https://api.github.com'


def get_all_keys(session):
    url = API_BASE + '/user/keys'
    while True:
        r = session.get(url)
        r.raise_for_status()

        for key in r.json():
            yield key

        if 'next' not in r.links:
            break

        url = r.links['next']['url']


def create_key(session, name, pubkey, check_mode):
    if check_mode:
        from datetime import datetime
        now = datetime.utcnow()
        return {
            'id': 0,
            'key': pubkey,
            'title': name,
            'url': 'http://example.com/CHECK_MODE_GITHUB_KEY',
            'created_at': datetime.strftime(now, '%Y-%m-%dT%H:%M:%SZ'),
            'read_only': False,
            'verified': False
        }
    else:
        response = session.post(
            API_BASE + '/user/keys',
            data=json.dumps({'title': name, 'key': pubkey}))
        response.raise_for_status()
        return response.json()


def delete_keys(session, to_delete, check_mode):
    if check_mode:
        return

    for key in to_delete:
        r = session.delete(API_BASE + '/user/keys/{[id]}'.format(key))
        r.raise_for_status()


def ensure_key_absent(session, name, check_mode):
    to_delete = [key for key in get_all_keys(session) if key['title'] == name]
    delete_keys(session, to_delete, check_mode=check_mode)

    return {'changed': bool(to_delete), 'deleted_keys': to_delete}


def ensure_key_present(session, name, pubkey, update, check_mode):
    matching = [k for k in get_all_keys(session) if k['title'] == name]
    changed = False

    if update and matching:
        delete_keys(session, matching, check_mode=check_mode)
        changed = True
        out['deleted_keys'] = matching

    if matching and not update:
        key = matching[0]
    else:
        changed = True
        key = create_key(session, name, pubkey, check_mode=check_mode)

    if update:
        (deleted_keys, matching_keys) = (matching, [])
    else:
        (deleted_keys, matching_keys) = ([], matching)

    return {
        'changed': changed,
        'deleted_keys': deleted_keys,
        'matching_keys': matching_keys,
        'key': key
    }


def main():
    argument_spec = {
        'token': {'required': True},
        'name': {'required': True},
        'pubkey': {'required': False},
        'state': {'choices': ['present', 'absent', 'updated'],
                  'default': 'present'},
    }
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    if not HAS_REQUESTS:
        module.fail_json(msg='this module requires the "requests" library')

    token = module.params['token']
    name = module.params['name']
    state = module.params['state']
    pubkey = module.params.get('pubkey')

    if state == 'present' and not pubkey:
        module.fail_json(
            msg='"pubkey" parameter is required when state is "present"')

    session = requests.Session()
    session.headers.update({
        'Authorization': 'token {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/vnd.github.v3+json',
    })
    try:
        if state == 'present':
            result = ensure_key_present(session, name, pubkey, update=False,
                                        check_mode=module.check_mode)
        elif state == 'updated':
            result = ensure_key_present(session, name, pubkey, update=True,
                                        check_mode=module.check_mode)
        elif state == 'absent':
            result = ensure_key_absent(session, name,
                                       check_mode=module.check_mode)
    except requests.RequestException, e:
        try:
            message = e.response.json()['message']
        except:
            message = '{} {}'.format(e, e.response.content)

        module.fail_json(msg='There was a problem managing a github key: {}'
                         .format(message))

    module.exit_json(**result)

from ansible.module_utils.basic import *  # noqa

if __name__ == '__main__':
    main()
