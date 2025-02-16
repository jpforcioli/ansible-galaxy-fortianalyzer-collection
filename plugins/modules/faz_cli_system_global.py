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
module: faz_cli_system_global
short_description: Global range attributes.
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
    cli_system_global:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            admin-lockout-duration:
                type: int
                default: 60
                description: 'Lockout duration(sec) for administration.'
            admin-lockout-threshold:
                type: int
                default: 3
                description: 'Lockout threshold for administration.'
            adom-mode:
                type: str
                default: 'normal'
                description:
                 - 'ADOM mode.'
                 - 'normal - Normal ADOM mode.'
                 - 'advanced - Advanced ADOM mode.'
                choices:
                    - 'normal'
                    - 'advanced'
            adom-select:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable select ADOM after login.'
                 - 'disable - Disable select ADOM after login.'
                 - 'enable - Enable select ADOM after login.'
                choices:
                    - 'disable'
                    - 'enable'
            adom-status:
                type: str
                default: 'disable'
                description:
                 - 'ADOM status.'
                 - 'disable - Disable ADOM mode.'
                 - 'enable - Enable ADOM mode.'
                choices:
                    - 'disable'
                    - 'enable'
            backup-compression:
                type: str
                default: 'normal'
                description:
                 - 'Compression level.'
                 - 'none - No compression.'
                 - 'low - Low compression (fastest).'
                 - 'normal - Normal compression.'
                 - 'high - Best compression (slowest).'
                choices:
                    - 'none'
                    - 'low'
                    - 'normal'
                    - 'high'
            backup-to-subfolders:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable creation of subfolders on server for backup storage.'
                 - 'disable - Disable creation of subfolders on server for backup storage.'
                 - 'enable - Enable creation of subfolders on server for backup storage.'
                choices:
                    - 'disable'
                    - 'enable'
            clone-name-option:
                type: str
                default: 'default'
                description:
                 - 'set the clone object names option.'
                 - 'default - Add a prefix of Clone of to the clone name.'
                 - 'keep - Keep the original name for user to edit.'
                choices:
                    - 'default'
                    - 'keep'
            clt-cert-req:
                type: str
                default: 'disable'
                description:
                 - 'Require client certificate for GUI login.'
                 - 'disable - Disable setting.'
                 - 'enable - Require client certificate for GUI login.'
                 - 'optional - Optional client certificate for GUI login.'
                choices:
                    - 'disable'
                    - 'enable'
                    - 'optional'
            console-output:
                type: str
                default: 'standard'
                description:
                 - 'Console output mode.'
                 - 'standard - Standard output.'
                 - 'more - More page output.'
                choices:
                    - 'standard'
                    - 'more'
            country-flag:
                type: str
                default: 'enable'
                description:
                 - 'Country flag Status.'
                 - 'disable - Disable country flag icon beside ip address.'
                 - 'enable - Enable country flag icon beside ip address.'
                choices:
                    - 'disable'
                    - 'enable'
            create-revision:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable create revision by default.'
                 - 'disable - Disable create revision by default.'
                 - 'enable - Enable create revision by default.'
                choices:
                    - 'disable'
                    - 'enable'
            daylightsavetime:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable daylight saving time.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            default-logview-auto-completion:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable log view filter auto-completion.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            default-search-mode:
                type: str
                default: 'filter-based'
                description:
                 - 'Set the default search mode of log view.'
                 - 'filter-based - Filter based search mode.'
                 - 'advanced - Advanced search mode.'
                choices:
                    - 'filter-based'
                    - 'advanced'
            detect-unregistered-log-device:
                type: str
                default: 'enable'
                description:
                 - 'Detect unregistered logging device from log message.'
                 - 'disable - Disable attribute function.'
                 - 'enable - Enable attribute function.'
                choices:
                    - 'disable'
                    - 'enable'
            device-view-mode:
                type: str
                default: 'regular'
                description:
                 - 'Set devices/groups view mode.'
                 - 'regular - Regular view mode.'
                 - 'tree - Tree view mode.'
                choices:
                    - 'regular'
                    - 'tree'
            dh-params:
                type: str
                default: '2048'
                description:
                 - 'Minimum size of Diffie-Hellman prime for SSH/HTTPS (bits).'
                 - '1024 - 1024 bits.'
                 - '1536 - 1536 bits.'
                 - '2048 - 2048 bits.'
                 - '3072 - 3072 bits.'
                 - '4096 - 4096 bits.'
                 - '6144 - 6144 bits.'
                 - '8192 - 8192 bits.'
                choices:
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
                    - '6144'
                    - '8192'
            disable-module:
                description: no description
                type: list
                choices:
                 - fortiview-noc
                 - siem
                 - soar
                 - none
                 - soc
                 - fortirecorder
                 - ai
            enc-algorithm:
                type: str
                default: 'high'
                description:
                 - 'SSL communication encryption algorithms.'
                 - 'low - SSL communication using all available encryption algorithms.'
                 - 'medium - SSL communication using high and medium encryption algorithms.'
                 - 'high - SSL communication using high encryption algorithms.'
                choices:
                    - 'low'
                    - 'medium'
                    - 'high'
            fgfm-ca-cert:
                type: str
                description: 'set the extra fgfm CA certificates.'
            fgfm-local-cert:
                type: str
                description: 'set the fgfm local certificate.'
            fgfm-ssl-protocol:
                type: str
                default: 'tlsv1.2'
                description:
                 - 'set the lowest SSL protocols for fgfmsd.'
                 - 'sslv3 - set SSLv3 as the lowest version.'
                 - 'tlsv1.0 - set TLSv1.0 as the lowest version.'
                 - 'tlsv1.1 - set TLSv1.1 as the lowest version.'
                 - 'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
                 - 'tlsv1.3 - set TLSv1.3 as the lowest version.'
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            ha-member-auto-grouping:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable automatically group HA members feature'
                 - 'disable - Disable automatically grouping HA members feature.'
                 - 'enable - Enable automatically grouping HA members only when group name is unique in your network.'
                choices:
                    - 'disable'
                    - 'enable'
            hitcount_concurrent:
                type: int
                default: 100
                description: 'The number of FortiGates that FortiManager polls at one time (10 - 500, default = 100).'
            hitcount_interval:
                type: int
                default: 900
                description: 'The interval for getting hit count from managed FortiGate devices, in seconds (60 - 86400, default = 900).'
            hostname:
                type: str
                default: 'FAZVM64'
                description: 'System hostname.'
            language:
                type: str
                default: 'english'
                description:
                 - 'System global language.'
                 - 'english - English'
                 - 'simch - Simplified Chinese'
                 - 'japanese - Japanese'
                 - 'korean - Korean'
                 - 'spanish - Spanish'
                 - 'trach - Traditional Chinese'
                choices:
                    - 'english'
                    - 'simch'
                    - 'japanese'
                    - 'korean'
                    - 'spanish'
                    - 'trach'
            latitude:
                type: str
                description: 'fmg location latitude'
            ldap-cache-timeout:
                type: int
                default: 86400
                description: 'LDAP browser cache timeout (seconds).'
            ldapconntimeout:
                type: int
                default: 60000
                description: 'LDAP connection timeout (msec).'
            lock-preempt:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable ADOM lock override.'
                 - 'disable - Disable lock preempt.'
                 - 'enable - Enable lock preempt.'
                choices:
                    - 'disable'
                    - 'enable'
            log-checksum:
                type: str
                default: 'none'
                description:
                 - 'Record log file hash value, timestamp, and authentication code at transmission or rolling.'
                 - 'none - No record log file checksum.'
                 - 'md5 - Record log files MD5 hash value only.'
                 - 'md5-auth - Record log files MD5 hash value and authentication code.'
                choices:
                    - 'none'
                    - 'md5'
                    - 'md5-auth'
            log-forward-cache-size:
                type: int
                default: 0
                description: 'Log forwarding disk cache size (GB).'
            log-mode:
                type: str
                default: 'analyzer'
                description:
                 - 'Log system operation mode.'
                 - 'analyzer - Operation mode is Analyzer'
                 - 'collector - Operation mode is Collector'
                choices:
                    - 'analyzer'
                    - 'collector'
            longitude:
                type: str
                description: 'fmg location longitude'
            max-aggregation-tasks:
                type: int
                default: 0
                description: 'Maximum number of concurrent tasks of a log aggregation session.'
            max-log-forward:
                type: int
                default: 5
                description: 'Maximum number of log-forward and aggregation settings.'
            max-running-reports:
                type: int
                default: 1
                description: 'Maximum number of reports generating at one time.'
            oftp-ssl-protocol:
                type: str
                default: 'tlsv1.2'
                description:
                 - 'set the lowest SSL protocols for oftpd.'
                 - 'sslv3 - set SSLv3 as the lowest version.'
                 - 'tlsv1.0 - set TLSv1.0 as the lowest version.'
                 - 'tlsv1.1 - set TLSv1.1 as the lowest version.'
                 - 'tlsv1.2 - set TLSv1.2 as the lowest version (default).'
                 - 'tlsv1.3 - set TLSv1.3 as the lowest version.'
                choices:
                    - 'sslv3'
                    - 'tlsv1.0'
                    - 'tlsv1.1'
                    - 'tlsv1.2'
                    - 'tlsv1.3'
            policy-hit-count:
                type: str
                default: 'disable'
                description:
                 - 'show policy hit count.'
                 - 'disable - Disable policy hit count.'
                 - 'enable - Enable policy hit count.'
                choices:
                    - 'disable'
                    - 'enable'
            policy-object-icon:
                type: str
                default: 'disable'
                description:
                 - 'show icons of policy objects.'
                 - 'disable - Disable icon of policy objects.'
                 - 'enable - Enable icon of policy objects.'
                choices:
                    - 'disable'
                    - 'enable'
            policy-object-in-dual-pane:
                type: str
                default: 'disable'
                description:
                 - 'show policies and objects in dual pane.'
                 - 'disable - Disable polices and objects in dual pane.'
                 - 'enable - Enable polices and objects in dual pane.'
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable pre-login banner.'
                 - 'disable - Disable pre-login banner.'
                 - 'enable - Enable pre-login banner.'
                choices:
                    - 'disable'
                    - 'enable'
            pre-login-banner-message:
                type: str
                description: 'Pre-login banner message.'
            private-data-encryption:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable private data encryption using an AES 128-bit key.'
                 - 'disable - Disable private data encryption using an AES 128-bit key.'
                 - 'enable - Enable private data encryption using an AES 128-bit key.'
                choices:
                    - 'disable'
                    - 'enable'
            remoteauthtimeout:
                type: int
                default: 10
                description: 'Remote authentication (RADIUS/LDAP) timeout (sec).'
            search-all-adoms:
                type: str
                default: 'disable'
                description:
                 - 'Enable/Disable Search all ADOMs for where-used query.'
                 - 'disable - Disable search all ADOMs for where-used queries.'
                 - 'enable - Enable search all ADOMs for where-used queries.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-low-encryption:
                type: str
                default: 'disable'
                description:
                 - 'SSL low-grade encryption.'
                 - 'disable - Disable SSL low-grade encryption.'
                 - 'enable - Enable SSL low-grade encryption.'
                choices:
                    - 'disable'
                    - 'enable'
            ssl-protocol:
                description: no description
                type: list
                choices:
                 - tlsv1.3
                 - tlsv1.2
                 - tlsv1.1
                 - tlsv1.0
                 - sslv3
            ssl-static-key-ciphers:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable SSL static key ciphers.'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            task-list-size:
                type: int
                default: 2000
                description: 'Maximum number of completed tasks to keep.'
            tftp:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable TFTP in `exec restore image` command (disabled by default in FIPS mode)'
                 - 'disable - Disable TFTP'
                 - 'enable - Enable TFTP'
                choices:
                    - 'disable'
                    - 'enable'
            timezone:
                type: str
                default: '04'
                description:
                 - 'Time zone.'
                 - '00 - (GMT-12:00) Eniwetak, Kwajalein.'
                 - '01 - (GMT-11:00) Midway Island, Samoa.'
                 - '02 - (GMT-10:00) Hawaii.'
                 - '03 - (GMT-9:00) Alaska.'
                 - '04 - (GMT-8:00) Pacific Time (US & Canada).'
                 - '05 - (GMT-7:00) Arizona.'
                 - '06 - (GMT-7:00) Mountain Time (US & Canada).'
                 - '07 - (GMT-6:00) Central America.'
                 - '08 - (GMT-6:00) Central Time (US & Canada).'
                 - '09 - (GMT-6:00) Mexico City.'
                 - '10 - (GMT-6:00) Saskatchewan.'
                 - '11 - (GMT-5:00) Bogota, Lima, Quito.'
                 - '12 - (GMT-5:00) Eastern Time (US & Canada).'
                 - '13 - (GMT-5:00) Indiana (East).'
                 - '14 - (GMT-4:00) Atlantic Time (Canada).'
                 - '15 - (GMT-4:00) La Paz.'
                 - '16 - (GMT-4:00) Santiago.'
                 - '17 - (GMT-3:30) Newfoundland.'
                 - '18 - (GMT-3:00) Brasilia.'
                 - '19 - (GMT-3:00) Buenos Aires, Georgetown.'
                 - '20 - (GMT-3:00) Nuuk (Greenland).'
                 - '21 - (GMT-2:00) Mid-Atlantic (Deprecated).'
                 - '22 - (GMT-1:00) Azores.'
                 - '23 - (GMT-1:00) Cape Verde Is.'
                 - '24 - (GMT) Monrovia.'
                 - '25 - (GMT) London, Edinburgh.'
                 - '26 - (GMT+1:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna.'
                 - '27 - (GMT+1:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague.'
                 - '28 - (GMT+1:00) Brussels, Copenhagen, Madrid, Paris.'
                 - '29 - (GMT+1:00) Sarajevo, Skopje, Warsaw, Zagreb.'
                 - '30 - (GMT+1:00) West Central Africa.'
                 - '31 - (GMT+2:00) Athens, Sofia, Vilnius.'
                 - '32 - (GMT+2:00) Bucharest.'
                 - '33 - (GMT+2:00) Cairo.'
                 - '34 - (GMT+2:00) Harare, Pretoria.'
                 - '35 - (GMT+2:00) Helsinki, Riga,Tallinn.'
                 - '36 - (GMT+2:00) Jerusalem.'
                 - '37 - (GMT+3:00) Baghdad.'
                 - '38 - (GMT+3:00) Kuwait, Riyadh.'
                 - '39 - (GMT+3:00) St.Petersburg, Volgograd.'
                 - '40 - (GMT+3:00) Nairobi.'
                 - '41 - (GMT+3:30) Tehran.'
                 - '42 - (GMT+4:00) Abu Dhabi, Muscat.'
                 - '43 - (GMT+4:00) Baku.'
                 - '44 - (GMT+4:30) Kabul.'
                 - '45 - (GMT+5:00) Ekaterinburg.'
                 - '46 - (GMT+5:00) Islamabad, Karachi, Tashkent.'
                 - '47 - (GMT+5:30) Calcutta, Chennai, Mumbai, New Delhi.'
                 - '48 - (GMT+5:45) Kathmandu.'
                 - '49 - (GMT+6:00) Almaty, Novosibirsk.'
                 - '50 - (GMT+6:00) Astana, Dhaka.'
                 - '51 - (GMT+5:30) Sri Jayawardenepura.'
                 - '52 - (GMT+6:30) Rangoon.'
                 - '53 - (GMT+7:00) Bangkok, Hanoi, Jakarta.'
                 - '54 - (GMT+7:00) Krasnoyarsk.'
                 - '55 - (GMT+8:00) Beijing, ChongQing, HongKong, Urumqi.'
                 - '56 - (GMT+8:00) Irkutsk, Ulaanbaatar.'
                 - '57 - (GMT+8:00) Kuala Lumpur, Singapore.'
                 - '58 - (GMT+8:00) Perth.'
                 - '59 - (GMT+8:00) Taipei.'
                 - '60 - (GMT+9:00) Osaka, Sapporo, Tokyo, Seoul.'
                 - '61 - (GMT+9:00) Yakutsk.'
                 - '62 - (GMT+9:30) Adelaide.'
                 - '63 - (GMT+9:30) Darwin.'
                 - '64 - (GMT+10:00) Brisbane.'
                 - '65 - (GMT+10:00) Canberra, Melbourne, Sydney.'
                 - '66 - (GMT+10:00) Guam, Port Moresby.'
                 - '67 - (GMT+10:00) Hobart.'
                 - '68 - (GMT+10:00) Vladivostok.'
                 - '69 - (GMT+11:00) Magadan.'
                 - '70 - (GMT+11:00) Solomon Is., New Caledonia.'
                 - '71 - (GMT+12:00) Auckland, Wellington.'
                 - '72 - (GMT+12:00) Fiji, Kamchatka, Marshall Is.'
                 - '73 - (GMT+13:00) Nukualofa.'
                 - '74 - (GMT-4:30) Caracas.'
                 - '75 - (GMT+1:00) Namibia.'
                 - '76 - (GMT-5:00) Brazil-Acre.'
                 - '77 - (GMT-4:00) Brazil-West.'
                 - '78 - (GMT-3:00) Brazil-East.'
                 - '79 - (GMT-2:00) Brazil-DeNoronha.'
                 - '80 - (GMT+14:00) Kiritimati.'
                 - '81 - (GMT-7:00) Baja California Sur, Chihuahua.'
                 - '82 - (GMT+12:45) Chatham Islands.'
                 - '83 - (GMT+3:00) Minsk.'
                 - '84 - (GMT+13:00) Samoa.'
                 - '85 - (GMT+3:00) Istanbul.'
                 - '86 - (GMT-4:00) Paraguay.'
                 - '87 - (GMT) Casablanca.'
                 - '88 - (GMT+3:00) Moscow.'
                 - '89 - (GMT) Greenwich Mean Time.'
                 - '90 - (GMT) Dublin.'
                 - '91 - (GMT) Lisbon.'
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '39'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '48'
                    - '49'
                    - '50'
                    - '51'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '61'
                    - '62'
                    - '63'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '73'
                    - '74'
                    - '75'
                    - '76'
                    - '77'
                    - '78'
                    - '79'
                    - '80'
                    - '81'
                    - '82'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
                    - '88'
                    - '89'
                    - '90'
                    - '91'
            tunnel-mtu:
                type: int
                default: 1500
                description: 'Maximum transportation unit(68 - 9000).'
            usg:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable Fortiguard server restriction.'
                 - 'disable - Contact any Fortiguard server'
                 - 'enable - Contact Fortiguard server in USA only'
                choices:
                    - 'disable'
                    - 'enable'
            webservice-proto:
                description: no description
                type: list
                choices:
                 - tlsv1.3
                 - tlsv1.2
                 - tlsv1.1
                 - tlsv1.0
                 - sslv3
                 - sslv2
            workflow-max-sessions:
                type: int
                default: 500
                description: 'Maximum number of workflow sessions per ADOM (minimum 100).'
            multiple-steps-upgrade-in-autolink:
                type: str
                default: 'disable'
                description:
                 - 'Enable/disable multiple steps upgade in autolink process'
                 - 'disable - Disable setting.'
                 - 'enable - Enable setting.'
                choices:
                    - 'disable'
                    - 'enable'
            object-revision-db-max:
                type: int
                default: 100000
                description: 'Maximum revisions for a single database (10,000-1,000,000 default 100,000).'
            object-revision-mandatory-note:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable mandatory note when create revision.'
                 - 'disable - Disable object revision.'
                 - 'enable - Enable object revision.'
                choices:
                    - 'disable'
                    - 'enable'
            object-revision-object-max:
                type: int
                default: 100
                description: 'Maximum revisions for a single object (10-1000 default 100).'
            object-revision-status:
                type: str
                default: 'enable'
                description:
                 - 'Enable/disable create revision when modify objects.'
                 - 'disable - Disable object revision.'
                 - 'enable - Enable object revision.'
                choices:
                    - 'disable'
                    - 'enable'

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
    - name: Global range attributes.
      faz_cli_system_global:
         bypass_validation: False
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         cli_system_global:
            admin-lockout-duration: <value of integer>
            admin-lockout-threshold: <value of integer>
            adom-mode: <value in [normal, advanced]>
            adom-select: <value in [disable, enable]>
            adom-status: <value in [disable, enable]>
            backup-compression: <value in [none, low, normal, ...]>
            backup-to-subfolders: <value in [disable, enable]>
            clone-name-option: <value in [default, keep]>
            clt-cert-req: <value in [disable, enable, optional]>
            console-output: <value in [standard, more]>
            country-flag: <value in [disable, enable]>
            create-revision: <value in [disable, enable]>
            daylightsavetime: <value in [disable, enable]>
            default-logview-auto-completion: <value in [disable, enable]>
            default-search-mode: <value in [filter-based, advanced]>
            detect-unregistered-log-device: <value in [disable, enable]>
            device-view-mode: <value in [regular, tree]>
            dh-params: <value in [1024, 1536, 2048, ...]>
            disable-module:
              - fortiview-noc
              - siem
              - soar
              - none
              - soc
              - fortirecorder
              - ai
            enc-algorithm: <value in [low, medium, high]>
            fgfm-ca-cert: <value of string>
            fgfm-local-cert: <value of string>
            fgfm-ssl-protocol: <value in [sslv3, tlsv1.0, tlsv1.1, ...]>
            ha-member-auto-grouping: <value in [disable, enable]>
            hitcount_concurrent: <value of integer>
            hitcount_interval: <value of integer>
            hostname: <value of string>
            language: <value in [english, simch, japanese, ...]>
            latitude: <value of string>
            ldap-cache-timeout: <value of integer>
            ldapconntimeout: <value of integer>
            lock-preempt: <value in [disable, enable]>
            log-checksum: <value in [none, md5, md5-auth]>
            log-forward-cache-size: <value of integer>
            log-mode: <value in [analyzer, collector]>
            longitude: <value of string>
            max-aggregation-tasks: <value of integer>
            max-log-forward: <value of integer>
            max-running-reports: <value of integer>
            oftp-ssl-protocol: <value in [sslv3, tlsv1.0, tlsv1.1, ...]>
            policy-hit-count: <value in [disable, enable]>
            policy-object-icon: <value in [disable, enable]>
            policy-object-in-dual-pane: <value in [disable, enable]>
            pre-login-banner: <value in [disable, enable]>
            pre-login-banner-message: <value of string>
            private-data-encryption: <value in [disable, enable]>
            remoteauthtimeout: <value of integer>
            search-all-adoms: <value in [disable, enable]>
            ssl-low-encryption: <value in [disable, enable]>
            ssl-protocol:
              - tlsv1.3
              - tlsv1.2
              - tlsv1.1
              - tlsv1.0
              - sslv3
            ssl-static-key-ciphers: <value in [disable, enable]>
            task-list-size: <value of integer>
            tftp: <value in [disable, enable]>
            timezone: <value in [00, 01, 02, ...]>
            tunnel-mtu: <value of integer>
            usg: <value in [disable, enable]>
            webservice-proto:
              - tlsv1.3
              - tlsv1.2
              - tlsv1.1
              - tlsv1.0
              - sslv3
              - sslv2
            workflow-max-sessions: <value of integer>
            multiple-steps-upgrade-in-autolink: <value in [disable, enable]>
            object-revision-db-max: <value of integer>
            object-revision-mandatory-note: <value in [disable, enable]>
            object-revision-object-max: <value of integer>
            object-revision-status: <value in [disable, enable]>

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
        '/cli/global/system/global'
    ]

    perobject_jrpc_urls = [
        '/cli/global/system/global/{global}'
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
        'cli_system_global': {
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
                'admin-lockout-duration': {
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
                'admin-lockout-threshold': {
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
                'adom-mode': {
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
                        'normal',
                        'advanced'
                    ],
                    'type': 'str'
                },
                'adom-select': {
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
                'adom-status': {
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
                'backup-compression': {
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
                        'low',
                        'normal',
                        'high'
                    ],
                    'type': 'str'
                },
                'backup-to-subfolders': {
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
                'clone-name-option': {
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
                        'default',
                        'keep'
                    ],
                    'type': 'str'
                },
                'clt-cert-req': {
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
                        'enable',
                        'optional'
                    ],
                    'type': 'str'
                },
                'console-output': {
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
                        'standard',
                        'more'
                    ],
                    'type': 'str'
                },
                'country-flag': {
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
                'create-revision': {
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
                'daylightsavetime': {
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
                'default-logview-auto-completion': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.2.6': False,
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
                'default-search-mode': {
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
                        'filter-based',
                        'advanced'
                    ],
                    'type': 'str'
                },
                'detect-unregistered-log-device': {
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
                'device-view-mode': {
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
                        'regular',
                        'tree'
                    ],
                    'type': 'str'
                },
                'dh-params': {
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
                        '1024',
                        '1536',
                        '2048',
                        '3072',
                        '4096',
                        '6144',
                        '8192'
                    ],
                    'type': 'str'
                },
                'disable-module': {
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
                        'fortiview-noc',
                        'siem',
                        'soar',
                        'none',
                        'soc',
                        'fortirecorder',
                        'ai'
                    ]
                },
                'enc-algorithm': {
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
                        'low',
                        'medium',
                        'high'
                    ],
                    'type': 'str'
                },
                'fgfm-ca-cert': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
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
                'fgfm-local-cert': {
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
                'fgfm-ssl-protocol': {
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
                        'sslv3',
                        'tlsv1.0',
                        'tlsv1.1',
                        'tlsv1.2',
                        'tlsv1.3'
                    ],
                    'type': 'str'
                },
                'ha-member-auto-grouping': {
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
                'hitcount_concurrent': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'hitcount_interval': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'type': 'int'
                },
                'hostname': {
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
                'language': {
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
                        'english',
                        'simch',
                        'japanese',
                        'korean',
                        'spanish',
                        'trach'
                    ],
                    'type': 'str'
                },
                'latitude': {
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
                'ldap-cache-timeout': {
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
                'ldapconntimeout': {
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
                'lock-preempt': {
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
                'log-checksum': {
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
                        'md5',
                        'md5-auth'
                    ],
                    'type': 'str'
                },
                'log-forward-cache-size': {
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
                'log-mode': {
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
                        'analyzer',
                        'collector'
                    ],
                    'type': 'str'
                },
                'longitude': {
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
                'max-aggregation-tasks': {
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
                'max-log-forward': {
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
                'max-running-reports': {
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
                'oftp-ssl-protocol': {
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
                        'sslv3',
                        'tlsv1.0',
                        'tlsv1.1',
                        'tlsv1.2',
                        'tlsv1.3'
                    ],
                    'type': 'str'
                },
                'policy-hit-count': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.2.6': True,
                        '6.4.1': True,
                        '6.4.2': True,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.5': False,
                        '7.0.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'policy-object-icon': {
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
                'policy-object-in-dual-pane': {
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
                'pre-login-banner': {
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
                'pre-login-banner-message': {
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
                'private-data-encryption': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
                        '6.2.2': False,
                        '6.2.3': False,
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
                'remoteauthtimeout': {
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
                'search-all-adoms': {
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
                'ssl-low-encryption': {
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
                'ssl-protocol': {
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
                        'tlsv1.3',
                        'tlsv1.2',
                        'tlsv1.1',
                        'tlsv1.0',
                        'sslv3'
                    ]
                },
                'ssl-static-key-ciphers': {
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
                'task-list-size': {
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
                'tftp': {
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
                'timezone': {
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
                        '00',
                        '01',
                        '02',
                        '03',
                        '04',
                        '05',
                        '06',
                        '07',
                        '08',
                        '09',
                        '10',
                        '11',
                        '12',
                        '13',
                        '14',
                        '15',
                        '16',
                        '17',
                        '18',
                        '19',
                        '20',
                        '21',
                        '22',
                        '23',
                        '24',
                        '25',
                        '26',
                        '27',
                        '28',
                        '29',
                        '30',
                        '31',
                        '32',
                        '33',
                        '34',
                        '35',
                        '36',
                        '37',
                        '38',
                        '39',
                        '40',
                        '41',
                        '42',
                        '43',
                        '44',
                        '45',
                        '46',
                        '47',
                        '48',
                        '49',
                        '50',
                        '51',
                        '52',
                        '53',
                        '54',
                        '55',
                        '56',
                        '57',
                        '58',
                        '59',
                        '60',
                        '61',
                        '62',
                        '63',
                        '64',
                        '65',
                        '66',
                        '67',
                        '68',
                        '69',
                        '70',
                        '71',
                        '72',
                        '73',
                        '74',
                        '75',
                        '76',
                        '77',
                        '78',
                        '79',
                        '80',
                        '81',
                        '82',
                        '83',
                        '84',
                        '85',
                        '86',
                        '87',
                        '88',
                        '89',
                        '90',
                        '91'
                    ],
                    'type': 'str'
                },
                'tunnel-mtu': {
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
                'usg': {
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
                'webservice-proto': {
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
                        'tlsv1.3',
                        'tlsv1.2',
                        'tlsv1.1',
                        'tlsv1.0',
                        'sslv3',
                        'sslv2'
                    ]
                },
                'workflow-max-sessions': {
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
                'multiple-steps-upgrade-in-autolink': {
                    'required': False,
                    'revision': {
                        '6.4.5': True,
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'object-revision-db-max': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'object-revision-mandatory-note': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'object-revision-object-max': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'type': 'int'
                },
                'object-revision-status': {
                    'required': False,
                    'revision': {
                        '7.0.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cli_system_global'),
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
