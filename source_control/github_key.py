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
      - SSH public key value. Required when state=present or state=updated.
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
import re


API_BASE = 'https://api.github.com'


class GitHubResponse(object):
    def __init__(self, response, info):
        self.content = response.read()
        self.info = info

    def json(self):
        return json.loads(self.content)

    def links(self):
        links = {}
        if 'link' in self.info:
            link_header = re.info['link']
            matches = re.findall('<([^>]+)>; rel="([^"]+)"', link_header)
            for url, rel in matches:
                links[rel] = url
        return links


class GitHubSession(object):
    def __init__(self, module, token):
        self.module = module
        self.token = token

    def request(self, method, url, data=None):
        headers = {
            'Authorization': 'token {}'.format(self.token),
            'Content-Type': 'application/json',
            'Accept': 'application/vnd.github.v3+json',
        }
        response, info = fetch_url(
            self.module, url, method=method, data=data, headers=headers)
        return GitHubResponse(response, info)


def get_all_keys(session):
    url = API_BASE + '/user/keys'
    while url:
        r = session.request('GET', url)
        for key in r.json():
            yield key

        url = r.links().get('next')


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
        return session.request(
            'POST',
            API_BASE + '/user/keys',
            data=json.dumps({'title': name, 'key': pubkey})).json()


def delete_keys(session, to_delete, check_mode):
    if check_mode:
        return

    for key in to_delete:
        session.request('DELETE', API_BASE + '/user/keys/{[id]}'.format(key))


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

    token = module.params['token']
    name = module.params['name']
    state = module.params['state']
    pubkey = module.params.get('pubkey')

    if state in ('present', 'updated') and not pubkey:
        module.fail_json(
            msg='"pubkey" parameter is required when state is "present"')

    session = GitHubSession(module, token)
    if state == 'present':
        result = ensure_key_present(session, name, pubkey, update=False,
                                    check_mode=module.check_mode)
    elif state == 'updated':
        result = ensure_key_present(session, name, pubkey, update=True,
                                    check_mode=module.check_mode)
    elif state == 'absent':
        result = ensure_key_absent(session, name,
                                   check_mode=module.check_mode)

    module.exit_json(**result)

from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.urls import *  # noqa

if __name__ == '__main__':
    main()
