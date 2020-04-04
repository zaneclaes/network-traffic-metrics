#!/usr/bin/env python3
import subprocess, time, re, socket, argparse, os, asyncio, sys
from prometheus_client import Counter, start_http_server

# Notes:
# Unsupported: ARP, nmap, and multicast
# Not sure about IPv6 tracking.

metric_labels = ['src', 'dst', 'service', 'proto']
service_map = {} # Loaded from /etc/services, service_map[port][proto] = service_name
services = set() # Names of all services

# Given an IP or FQDN, extract the domain name to be used as server/client.
def extract_domain(string):
    if opts.fqdn: return string
    parts = string.split('.')
    l = len(parts)
    if l == 4 and all(p.isnumeric() for p in parts): return string # IP Address
    return '.'.join(parts[l-2:]) if l > 2 else string

# Use the data loaded from /etc/services to determine the service name for a port+proto
def lookup_service(port, proto):
    if not port in service_map: return None
    if not proto in service_map[port]: return None
    return service_map[port][proto]

# Helper for building regex.
def re_param(name, pattern):
    return f'(?P<{name}>{pattern})'

# Pre-compile regex for matching tcpdump output:
pattern = '.*' + '.*'.join([
    'proto ' + re_param('proto', '\w+') + ' ',
    'length ' + re_param('length', '\d+'),
    '\n\s*' + re_param('src', '[\w\d\.-]+') + '\.' + re_param('srcp', '[\w\d-]+') +
    ' > ' +
    re_param('dst', '[\w\d\.-]+') + '\.' + re_param('dstp', '[\w\d-]+'),
]) + '.*'
dump_matcher = re.compile(pattern)

# Parse output from tcpdump and update the Prometheus counters.
def parse_packet(line):
    m = dump_matcher.match(line)
    if not m:
        print('[SKIP] ' + line.replace("\n", "\t"))
        return

    labels = {
        'src': extract_domain(m.group('src')),
        'dst': extract_domain(m.group('dst')),
        'proto': m.group('proto').lower(),
        'service': None
    }
    # If the last part of the src/dst is a service, just use the literal service name:
    if m.group('dstp') in services: labels['service'] = m.group('dstp')
    elif m.group('srcp') in services: labels['service'] = m.group('srcp')
    # Otherwise, do a lookup of port/proto to the service:
    if not labels['service'] and m.group('dstp').isnumeric():
        labels['service'] = lookup_service(int(m.group('dstp')), labels['proto'])
    if not labels['service'] and m.group('srcp').isnumeric():
        labels['service'] = lookup_service(int(m.group('srcp')), labels['proto'])
    if not labels['service']:
        labels['service'] = ""

    packets.labels(**labels).inc()
    throughput.labels(**labels).inc(int(m.group('length')))

# Run tcpdump and stream the packets out
async def stream_packets():
    p = await asyncio.create_subprocess_exec(
        'tcpdump', '-i', opts.interface, '-v', '-l', opts.filters,
        stdout=asyncio.subprocess.PIPE)
    while True:
        # When tcpdump is run with -v, it outputs two lines per packet;
        # readuntil ensures that each "line" is actually a parse-able string of output.
        line = await p.stdout.readuntil(b' IP ')
        if len(line) <= 0:
            print(f'No output from tcpdump... waiting.')
            time.sleep(1)
            continue
        try:
            parse_packet(line.decode('utf-8'))
        except BaseException as e:
            print(f'Failed to parse line "{line}" because: {e}')

if __name__ == '__main__':
    # Load a map of ports to services from /etc/services:
    matcher = re.compile('(?P<service>\w+)\s*(?P<port>\d+)/(?P<proto>\w+)')
    with open('/etc/services') as f:
        for line in f.readlines():
            match = matcher.match(line)
            if not match: continue
            port = int(match.group('port'))
            if not port in services: service_map[port] = {}
            service_map[port][match.group('proto')] = match.group('service')
            services.add(match.group('service'))

    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default=os.getenv('NTM_INTERFACE', 'eth0'),
        help='The network interface to monitor.')
    parser.add_argument('--port', '-p', default=int(os.getenv('NTM_PORT', 8000)),
        help='The Prometheus metrics port.')
    parser.add_argument('--metric_prefix', '-s', default=os.getenv('NTM_METRIC_PREFIX', 'ntm'),
        help='Metric prefix (group) for Prometheus')
    parser.add_argument('--fqdn', '-f', action='store_true',
        help='Include the FQDN (will increase cardinality of metrics significantly)')
    parser.add_argument('filters', nargs='?', default=os.getenv('NTM_FILTERS', ''),
        help='The TCPdump filters, e.g., "src net 192.168.1.1/24"')
    opts = parser.parse_args()

    packets = Counter(f'{opts.metric_prefix}_packets', 'Packets transferred', metric_labels)
    throughput = Counter(f'{opts.metric_prefix}_bytes', 'Bytes transferred', metric_labels)

    start_http_server(int(opts.port))
    asyncio.run(stream_packets())