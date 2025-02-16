#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2021 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: faz_cli_system_log_settings
short_description: Log settings.
description:
    - This module is able to configure a FortiAnalyzer device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.11"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    enable_log:
        description: Enable/Disable logging for task
        required: false
        type: bool
        default: false
    proposed_method:
        description: The overridden method for the underlying Json RPC request
        required: false
        type: str
        choices:
          - update
          - set
          - add
    bypass_validation:
        description: only set to True when module schema diffs with FortiAnalyzer API structure, module continues to execute without validating parameters
        required: false
        type: bool
        default: false
    state:
        description: the directive to create, update or delete an object
        type: str
        required: true
        choices:
          - present
          - absent
    rc_succeeded:
        description: the rc codes list with which the conditions to succeed will be overriden
        type: list
        required: false
    rc_failed:
        description: the rc codes list with which the conditions to fail will be overriden
        type: list
        required: false
    cli_system_log_settings:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            FAC-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FAZ-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FCH-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FCT-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FDD-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FGT-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FMG-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FML-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FPX-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FSA-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            FWB-custom-field1:
                type: str
                description: 'Name of custom log field to index.'
            browse-max-logfiles:
                type: int
                default: 10000
                description: 'Maximum number of log files for each log browse attempt for each Adom.'
            dns-resolve-dstip:
                type: str
                default: 'disable'
                description:
                 - 'Enable/Disable resolving destination IP by DNS.'
                 - 'disable - Disable resolving destination IP by DNS.'
                 - 'enable - Enable resolving destination IP by DNS.'
                choices:
                    - 'disable'
                    - 'enable'
            download-max-logs:
                type: int
                default: 100000
                description: 'Maximum number of logs for each log download attempt.'
            ha-auto-migrate:
                type: str
                default: 'disable'
                description:
                 - 'Enabled/Disable automatically merging HA members logs to HA cluster.'
                 - 'disable - Disable automatically merging HA members logs to HA cluster.'
                 - 'enable - Enable automatically merging HA members logs to HA cluster.'
                choices:
                    - 'disable'
                    - 'enable'
            import-max-logfiles:
                type: int
                default: 10000
                description: 'Maximum number of log files for each log import attempt.'
            log-file-archive-name:
                type: str
                default: 'basic'
                description:
                 - 'Log file name format for archiving, such as backup, upload or download.'
                 - 'basic - Basic format for log archive file name, e.g. FGT20C0000000001.tlog.1417797247.log.'
                 - 'extended - Extended format for log archive file name, e.g. FGT20C0000000001.2014-12-05-08:34:58.tlog.1417797247.log.'
                choices:
                    - 'basic'
                    - 'extended'
            rolling-analyzer:
                description: no description
                type: dict
                required: false
                suboptions:
                    days:
                        description: no description
                        type: list
                        choices:
                         - sun
                         - mon
                         - tue
                         - wed
                         - thu
                         - fri
                         - sat
                    del-files:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable log file deletion after uploading.'
                         - 'disable - Disable log file deletion.'
                         - 'enable - Enable log file deletion.'
                        choices:
                            - 'disable'
                            - 'enable'
                    directory:
                        type: str
                        description: 'Upload server directory, for Unix server, use absolute'
                    file-size:
                        type: int
                        default: 200
                        description: 'Roll log files when they reach this size (MB).'
                    gzip-format:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable compression of uploaded log files.'
                         - 'disable - Disable compression.'
                         - 'enable - Enable compression.'
                        choices:
                            - 'disable'
                            - 'enable'
                    hour:
                        type: int
                        default: 0
                        description: 'Log files rolling schedule (hour).'
                    ip:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP address.'
                    ip2:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP2 address.'
                    ip3:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP3 address.'
                    log-format:
                        type: str
                        default: 'native'
                        description:
                         - 'Format of uploaded log files.'
                         - 'native - Native format (text or compact).'
                         - 'text - Text format (convert if necessary).'
                         - 'csv - CSV (comma-separated value) format.'
                        choices:
                            - 'native'
                            - 'text'
                            - 'csv'
                    min:
                        type: int
                        default: 0
                        description: 'Log files rolling schedule (minutes).'
                    password:
                        description: no description
                        type: str
                    password2:
                        description: no description
                        type: str
                    password3:
                        description: no description
                        type: str
                    port:
                        type: int
                        default: 0
                        description: 'Upload server IP1 port number.'
                    port2:
                        type: int
                        default: 0
                        description: 'Upload server IP2 port number.'
                    port3:
                        type: int
                        default: 0
                        description: 'Upload server IP3 port number.'
                    server-type:
                        type: str
                        default: 'ftp'
                        description:
                         - 'Upload server type.'
                         - 'ftp - Upload via FTP.'
                         - 'sftp - Upload via SFTP.'
                         - 'scp - Upload via SCP.'
                        choices:
                            - 'ftp'
                            - 'sftp'
                            - 'scp'
                    upload:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable log file uploads.'
                         - 'disable - Disable log files uploading.'
                         - 'enable - Enable log files uploading.'
                        choices:
                            - 'disable'
                            - 'enable'
                    upload-hour:
                        type: int
                        default: 0
                        description: 'Log files upload schedule (hour).'
                    upload-mode:
                        type: str
                        default: 'backup'
                        description:
                         - 'Upload mode with multiple servers.'
                         - 'backup - Servers are attempted and used one after the other upon failure to connect.'
                         - 'mirror - All configured servers are attempted and used.'
                        choices:
                            - 'backup'
                            - 'mirror'
                    upload-trigger:
                        type: str
                        default: 'on-roll'
                        description:
                         - 'Event triggering log files upload.'
                         - 'on-roll - Upload log files after they are rolled.'
                         - 'on-schedule - Upload log files daily.'
                        choices:
                            - 'on-roll'
                            - 'on-schedule'
                    username:
                        type: str
                        description: 'Upload server login username.'
                    username2:
                        type: str
                        description: 'Upload server login username2.'
                    username3:
                        type: str
                        description: 'Upload server login username3.'
                    when:
                        type: str
                        default: 'none'
                        description:
                         - 'Roll log files periodically.'
                         - 'none - Do not roll log files periodically.'
                         - 'daily - Roll log files daily.'
                         - 'weekly - Roll log files on certain days of week.'
                        choices:
                            - 'none'
                            - 'daily'
                            - 'weekly'
            rolling-local:
                description: no description
                type: dict
                required: false
                suboptions:
                    days:
                        description: no description
                        type: list
                        choices:
                         - sun
                         - mon
                         - tue
                         - wed
                         - thu
                         - fri
                         - sat
                    del-files:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable log file deletion after uploading.'
                         - 'disable - Disable log file deletion.'
                         - 'enable - Enable log file deletion.'
                        choices:
                            - 'disable'
                            - 'enable'
                    directory:
                        type: str
                        description: 'Upload server directory, for Unix server, use absolute'
                    file-size:
                        type: int
                        default: 200
                        description: 'Roll log files when they reach this size (MB).'
                    gzip-format:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable compression of uploaded log files.'
                         - 'disable - Disable compression.'
                         - 'enable - Enable compression.'
                        choices:
                            - 'disable'
                            - 'enable'
                    hour:
                        type: int
                        default: 0
                        description: 'Log files rolling schedule (hour).'
                    ip:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP address.'
                    ip2:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP2 address.'
                    ip3:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP3 address.'
                    log-format:
                        type: str
                        default: 'native'
                        description:
                         - 'Format of uploaded log files.'
                         - 'native - Native format (text or compact).'
                         - 'text - Text format (convert if necessary).'
                         - 'csv - CSV (comma-separated value) format.'
                        choices:
                            - 'native'
                            - 'text'
                            - 'csv'
                    min:
                        type: int
                        default: 0
                        description: 'Log files rolling schedule (minutes).'
                    password:
                        description: no description
                        type: str
                    password2:
                        description: no description
                        type: str
                    password3:
                        description: no description
                        type: str
                    port:
                        type: int
                        default: 0
                        description: 'Upload server IP1 port number.'
                    port2:
                        type: int
                        default: 0
                        description: 'Upload server IP2 port number.'
                    port3:
                        type: int
                        default: 0
                        description: 'Upload server IP3 port number.'
                    server-type:
                        type: str
                        default: 'ftp'
                        description:
                         - 'Upload server type.'
                         - 'ftp - Upload via FTP.'
                         - 'sftp - Upload via SFTP.'
                         - 'scp - Upload via SCP.'
                        choices:
                            - 'ftp'
                            - 'sftp'
                            - 'scp'
                    upload:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable log file uploads.'
                         - 'disable - Disable log files uploading.'
                         - 'enable - Enable log files uploading.'
                        choices:
                            - 'disable'
                            - 'enable'
                    upload-hour:
                        type: int
                        default: 0
                        description: 'Log files upload schedule (hour).'
                    upload-mode:
                        type: str
                        default: 'backup'
                        description:
                         - 'Upload mode with multiple servers.'
                         - 'backup - Servers are attempted and used one after the other upon failure to connect.'
                         - 'mirror - All configured servers are attempted and used.'
                        choices:
                            - 'backup'
                            - 'mirror'
                    upload-trigger:
                        type: str
                        default: 'on-roll'
                        description:
                         - 'Event triggering log files upload.'
                         - 'on-roll - Upload log files after they are rolled.'
                         - 'on-schedule - Upload log files daily.'
                        choices:
                            - 'on-roll'
                            - 'on-schedule'
                    username:
                        type: str
                        description: 'Upload server login username.'
                    username2:
                        type: str
                        description: 'Upload server login username2.'
                    username3:
                        type: str
                        description: 'Upload server login username3.'
                    when:
                        type: str
                        default: 'none'
                        description:
                         - 'Roll log files periodically.'
                         - 'none - Do not roll log files periodically.'
                         - 'daily - Roll log files daily.'
                         - 'weekly - Roll log files on certain days of week.'
                        choices:
                            - 'none'
                            - 'daily'
                            - 'weekly'
            rolling-regular:
                description: no description
                type: dict
                required: false
                suboptions:
                    days:
                        description: no description
                        type: list
                        choices:
                         - sun
                         - mon
                         - tue
                         - wed
                         - thu
                         - fri
                         - sat
                    del-files:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable log file deletion after uploading.'
                         - 'disable - Disable log file deletion.'
                         - 'enable - Enable log file deletion.'
                        choices:
                            - 'disable'
                            - 'enable'
                    directory:
                        type: str
                        description: 'Upload server directory, for Unix server, use absolute'
                    file-size:
                        type: int
                        default: 200
                        description: 'Roll log files when they reach this size (MB).'
                    gzip-format:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable compression of uploaded log files.'
                         - 'disable - Disable compression.'
                         - 'enable - Enable compression.'
                        choices:
                            - 'disable'
                            - 'enable'
                    hour:
                        type: int
                        default: 0
                        description: 'Log files rolling schedule (hour).'
                    ip:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP address.'
                    ip2:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP2 address.'
                    ip3:
                        type: str
                        default: '0.0.0.0'
                        description: 'Upload server IP3 address.'
                    log-format:
                        type: str
                        default: 'native'
                        description:
                         - 'Format of uploaded log files.'
                         - 'native - Native format (text or compact).'
                         - 'text - Text format (convert if necessary).'
                         - 'csv - CSV (comma-separated value) format.'
                        choices:
                            - 'native'
                            - 'text'
                            - 'csv'
                    min:
                        type: int
                        default: 0
                        description: 'Log files rolling schedule (minutes).'
                    password:
                        description: no description
                        type: str
                    password2:
                        description: no description
                        type: str
                    password3:
                        description: no description
                        type: str
                    port:
                        type: int
                        default: 0
                        description: 'Upload server IP1 port number.'
                    port2:
                        type: int
                        default: 0
                        description: 'Upload server IP2 port number.'
                    port3:
                        type: int
                        default: 0
                        description: 'Upload server IP3 port number.'
                    server-type:
                        type: str
                        default: 'ftp'
                        description:
                         - 'Upload server type.'
                         - 'ftp - Upload via FTP.'
                         - 'sftp - Upload via SFTP.'
                         - 'scp - Upload via SCP.'
                        choices:
                            - 'ftp'
                            - 'sftp'
                            - 'scp'
                    upload:
                        type: str
                        default: 'disable'
                        description:
                         - 'Enable/disable log file uploads.'
                         - 'disable - Disable log files uploading.'
                         - 'enable - Enable log files uploading.'
                        choices:
                            - 'disable'
                            - 'enable'
                    upload-hour:
                        type: int
                        default: 0
                        description: 'Log files upload schedule (hour).'
                    upload-mode:
                        type: str
                        default: 'backup'
                        description:
                         - 'Upload mode with multiple servers.'
                         - 'backup - Servers are attempted and used one after the other upon failure to connect.'
                         - 'mirror - All configured servers are attempted and used.'
                        choices:
                            - 'backup'
                            - 'mirror'
                    upload-trigger:
                        type: str
                        default: 'on-roll'
                        description:
                         - 'Event triggering log files upload.'
                         - 'on-roll - Upload log files after they are rolled.'
                         - 'on-schedule - Upload log files daily.'
                        choices:
                            - 'on-roll'
                            - 'on-schedule'
                    username:
                        type: str
                        description: 'Upload server login username.'
                    username2:
                        type: str
                        description: 'Upload server login username2.'
                    username3:
                        type: str
                        description: 'Upload server login username3.'
                    when:
                        type: str
                        default: 'none'
                        description:
                         - 'Roll log files periodically.'
                         - 'none - Do not roll log files periodically.'
                         - 'daily - Roll log files daily.'
                         - 'weekly - Roll log files on certain days of week.'
                        choices:
                            - 'none'
                            - 'daily'
                            - 'weekly'
            sync-search-timeout:
                type: int
                default: 60
                description: 'Maximum number of seconds for running a log search session in synchronous mode.'

'''

EXAMPLES = '''
 - hosts: fortianalyzer-inventory
   collections:
     - fortinet.fortianalyzer
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Log settings.
      faz_cli_system_log_settings:
         bypass_validation: False
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         cli_system_log_settings:
            FAC-custom-field1: <value of string>
            FAZ-custom-field1: <value of string>
            FCH-custom-field1: <value of string>
            FCT-custom-field1: <value of string>
            FDD-custom-field1: <value of string>
            FGT-custom-field1: <value of string>
            FMG-custom-field1: <value of string>
            FML-custom-field1: <value of string>
            FPX-custom-field1: <value of string>
            FSA-custom-field1: <value of string>
            FWB-custom-field1: <value of string>
            browse-max-logfiles: <value of integer>
            dns-resolve-dstip: <value in [disable, enable]>
            download-max-logs: <value of integer>
            ha-auto-migrate: <value in [disable, enable]>
            import-max-logfiles: <value of integer>
            log-file-archive-name: <value in [basic, extended]>
            rolling-analyzer:
               days:
                 - sun
                 - mon
                 - tue
                 - wed
                 - thu
                 - fri
                 - sat
               del-files: <value in [disable, enable]>
               directory: <value of string>
               file-size: <value of integer>
               gzip-format: <value in [disable, enable]>
               hour: <value of integer>
               ip: <value of string>
               ip2: <value of string>
               ip3: <value of string>
               log-format: <value in [native, text, csv]>
               min: <value of integer>
               password: <value of string>
               password2: <value of string>
               password3: <value of string>
               port: <value of integer>
               port2: <value of integer>
               port3: <value of integer>
               server-type: <value in [ftp, sftp, scp]>
               upload: <value in [disable, enable]>
               upload-hour: <value of integer>
               upload-mode: <value in [backup, mirror]>
               upload-trigger: <value in [on-roll, on-schedule]>
               username: <value of string>
               username2: <value of string>
               username3: <value of string>
               when: <value in [none, daily, weekly]>
            rolling-local:
               days:
                 - sun
                 - mon
                 - tue
                 - wed
                 - thu
                 - fri
                 - sat
               del-files: <value in [disable, enable]>
               directory: <value of string>
               file-size: <value of integer>
               gzip-format: <value in [disable, enable]>
               hour: <value of integer>
               ip: <value of string>
               ip2: <value of string>
               ip3: <value of string>
               log-format: <value in [native, text, csv]>
               min: <value of integer>
               password: <value of string>
               password2: <value of string>
               password3: <value of string>
               port: <value of integer>
               port2: <value of integer>
               port3: <value of integer>
               server-type: <value in [ftp, sftp, scp]>
               upload: <value in [disable, enable]>
               upload-hour: <value of integer>
               upload-mode: <value in [backup, mirror]>
               upload-trigger: <value in [on-roll, on-schedule]>
               username: <value of string>
               username2: <value of string>
               username3: <value of string>
               when: <value in [none, daily, weekly]>
            rolling-regular:
               days:
                 - sun
                 - mon
                 - tue
                 - wed
                 - thu
                 - fri
                 - sat
               del-files: <value in [disable, enable]>
               directory: <value of string>
               file-size: <value of integer>
               gzip-format: <value in [disable, enable]>
               hour: <value of integer>
               ip: <value of string>
               ip2: <value of string>
               ip3: <value of string>
               log-format: <value in [native, text, csv]>
               min: <value of integer>
               password: <value of string>
               password2: <value of string>
               password3: <value of string>
               port: <value of integer>
               port2: <value of integer>
               port3: <value of integer>
               server-type: <value in [ftp, sftp, scp]>
               upload: <value in [disable, enable]>
               upload-hour: <value of integer>
               upload-mode: <value in [backup, mirror]>
               upload-trigger: <value in [on-roll, on-schedule]>
               username: <value of string>
               username2: <value of string>
               username3: <value of string>
               when: <value in [none, daily, weekly]>
            sync-search-timeout: <value of integer>

'''

RETURN = '''
request_url:
    description: The full url requested
    returned: always
    type: str
    sample: /sys/login/user
response_code:
    description: The status of api request
    returned: always
    type: int
    sample: 0
response_message:
    description: The descriptive message of the api response
    type: str
    returned: always
    sample: OK.

'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortianalyzer.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/cli/global/system/log/settings'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/log/settings/{settings}'
    ]

    url_params = []
    module_primary_key = None
    module_arg_spec = {
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list'
        },
        'rc_failed': {
            'required': False,
            'type': 'list'
        },
        'cli_system_log_settings': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '7.0.0': True
            },
            'options': {
                'FAC-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FAZ-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FCH-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FCT-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FDD-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FGT-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FMG-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FML-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FPX-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FSA-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'FWB-custom-field1': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'str'
                },
                'browse-max-logfiles': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'dns-resolve-dstip': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'download-max-logs': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'ha-auto-migrate': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'import-max-logfiles': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'log-file-archive-name': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'basic',
                        'extended'
                    ],
                    'type': 'str'
                },
                'rolling-analyzer': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'days': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'sun',
                                'mon',
                                'tue',
                                'wed',
                                'thu',
                                'fri',
                                'sat'
                            ]
                        },
                        'del-files': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'directory': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'file-size': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'gzip-format': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'hour': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'ip2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'ip3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'log-format': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'native',
                                'text',
                                'csv'
                            ],
                            'type': 'str'
                        },
                        'min': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'password': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'password2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'password3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'port2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'port3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'server-type': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'ftp',
                                'sftp',
                                'scp'
                            ],
                            'type': 'str'
                        },
                        'upload': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'upload-hour': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'upload-mode': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'backup',
                                'mirror'
                            ],
                            'type': 'str'
                        },
                        'upload-trigger': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'on-roll',
                                'on-schedule'
                            ],
                            'type': 'str'
                        },
                        'username': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'username2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'username3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'when': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'daily',
                                'weekly'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'rolling-local': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'days': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'sun',
                                'mon',
                                'tue',
                                'wed',
                                'thu',
                                'fri',
                                'sat'
                            ]
                        },
                        'del-files': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'directory': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'file-size': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'gzip-format': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'hour': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'ip2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'ip3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'log-format': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'native',
                                'text',
                                'csv'
                            ],
                            'type': 'str'
                        },
                        'min': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'password': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'password2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'password3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'port2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'port3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'server-type': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'ftp',
                                'sftp',
                                'scp'
                            ],
                            'type': 'str'
                        },
                        'upload': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'upload-hour': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'upload-mode': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'backup',
                                'mirror'
                            ],
                            'type': 'str'
                        },
                        'upload-trigger': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'on-roll',
                                'on-schedule'
                            ],
                            'type': 'str'
                        },
                        'username': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'username2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'username3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'when': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'daily',
                                'weekly'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'rolling-regular': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'days': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'sun',
                                'mon',
                                'tue',
                                'wed',
                                'thu',
                                'fri',
                                'sat'
                            ]
                        },
                        'del-files': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'directory': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'file-size': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'gzip-format': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'hour': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'ip2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'ip3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'log-format': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'native',
                                'text',
                                'csv'
                            ],
                            'type': 'str'
                        },
                        'min': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'password': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'password2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'password3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'port2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'port3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'server-type': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'ftp',
                                'sftp',
                                'scp'
                            ],
                            'type': 'str'
                        },
                        'upload': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'upload-hour': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'int'
                        },
                        'upload-mode': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'backup',
                                'mirror'
                            ],
                            'type': 'str'
                        },
                        'upload-trigger': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'on-roll',
                                'on-schedule'
                            ],
                            'type': 'str'
                        },
                        'username': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'username2': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'username3': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'type': 'str'
                        },
                        'when': {
                            'required': False,
                            'revision': {
                                '6.2.1': True,
                                '6.2.2': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.2.6': True,
                                '6.4.1': True,
                                '6.4.2': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.5': True,
                                '7.0.0': True
                            },
                            'choices': [
                                'none',
                                'daily',
                                'weekly'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'sync-search-timeout': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'type': 'int'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_log_settings'),
                           supports_check_mode=False)

    faz = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        faz = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        faz.validate_parameters(params_validation_blob)
        faz.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
