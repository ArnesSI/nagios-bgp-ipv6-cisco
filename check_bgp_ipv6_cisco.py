#!/usr/bin/env python
#
# MIT License
#
# Copyright (c) 2017 Matej Vadnjal <matej@arnes.si>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
#
# Check status of IPv6 BGP peers on a Cisco IOS device.
#
# Example call:
# check_bgp_ipv6_cisco.py -H myrouter -l admin -p admin
#

from pynag.Plugins import PluginHelper, ok, warning, critical, unknown
import re
import netmiko

def get_peers(device, debug=False):
    result = {}
    command = 'show bgp ipv6 unicast neighbors'
    output = device.send_command(command)
    if output.strip().startswith('% '):
        result['error'] = output
    else:
        if debug:
            print output
        result['success'] = {'peers': [], 'counts': {}}
        peer = {
            'address': None,
            'as': None,
            'description': None,
            'state': None,
            'status': None
        }
        for line in output.split('\n'):
            new_peer = re.search(r'^BGP neighbor is (?P<peer_addr>[0-9a-fA-F:]+),(?:.*remote AS (?P<peer_as>\d+))?', line)
            if new_peer:
                if peer.get('address'):
                    result['success']['peers'].append(peer)
                peer = {
                    'address': new_peer.group('peer_addr'),
                    'as': new_peer.group('peer_as'),
                    'description': None,
                    'state': None,
                }
            desc_match = re.search(r'^ Description: (?P<description>.+)$', line)
            if desc_match and peer.get('address'):
                peer['description'] = desc_match.group('description')
            state_match = re.search(r'^  BGP state = (?P<state>[^,\s]+)', line)
            if state_match and peer.get('address'):
                peer['state'] = state_match.group('state')
                peer['status'] = get_status(peer['state'])
        if peer.get('address'):
            result['success']['peers'].append(peer)
        result['success']['counts'] = get_counts(result['success']['peers'])
    return result

def get_status(state):
    if 'Active' in state:
        return critical
    elif 'Idle' in state:
        return critical
    elif 'Established':
        return ok
    else:
        return critical

def get_peer_line(peer):
    status = get_status(peer['state'])
    if status == critical:
        state_colorized = colorize(peer['state'], 'red')
    elif status == warning:
        state_colorized = colorize(peer['state'], 'orange')
    elif status == ok:
        state_colorized = colorize(peer['state'], 'green')
    else:
        state_colorized = colorize(peer['state'], 'purple')
    text = '%s [%s / %s]: %s' % (peer['address'], peer['as'], peer['description'], state_colorized)
    return text

def get_counts(peers):
    return {
        'total': len(peers),
        'established': len([peer for peer in peers if 'Established' in peer['state']]),
        'active': len([peer for peer in peers if 'Active' in peer['state']]),
        'idle': len([peer for peer in peers if 'Idle' in peer['state']]),
    }

def get_stats_line(counts):
    return 'Total:%d,Estab:%d,Active:%d,Idle:%d' % (
        counts['total'],
        counts['established'],
        counts['active'],
        counts['idle'],
    )

def colorize(text, color=None):
    if helper.options.html and color:
        text = '<span style="font-weight:bold; color:%s;">%s</span>' % (color, text)
    return text

helper = PluginHelper()
helper.parser.add_option("-H", help="Host to connect to (default: %default)", dest="host", default='localhost')
helper.parser.add_option("-l", help="Username to login with", dest="username")
helper.parser.add_option("-p", help="Password to login with", dest="password")
helper.parser.add_option("--html", help="Enable HTML output", dest="html", action="store_true", default=False)
helper.parse_arguments()

conf = {
    'device_type':'cisco_ios',
    'host':helper.options.host,
    'username':helper.options.username,
    'password':helper.options.password
}
device = netmiko.ConnectHandler(**conf)
result = get_peers(
    device=device,
    debug=helper.options.show_debug
)
if helper.options.show_debug:
    print result

if 'error' in result:
    helper.status(unknown)
    helper.add_summary('%s: unable to check')
    helper.add_long_output(result['error'])
elif 'success' in result:
    if not result['success']['peers']:
        helper.status(warning)
        helper.add_summary('No IPv6 BGP peers configured')
    not_ok_count = result['success']['counts']['active'] + result['success']['counts']['idle']
    if not_ok_count:
        helper.status(critical)
        helper.add_summary('%s peers in non OK state' % not_ok_count)
    else:
        helper.status(ok)
        helper.add_summary('All %s peers OK' % result['success']['counts']['total'])
    helper.add_long_output(get_stats_line(result['success']['counts']))
    for peer in result['success']['peers']:
        peer_line = get_peer_line(peer)
        helper.add_long_output(peer_line)
else:
    helper.status(unknown)
    helper.add_summary('Unrecognized result')
    helper.add_long_output(str(result))

helper.exit()
