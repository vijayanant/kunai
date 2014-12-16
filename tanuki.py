import os
import sys
import argparse
import requests as rq
import socket

# DO NOT FORGEET:
# sysctl -w net.core.rmem_max=26214400

from kunai.cluster import Cluster
from kunai.log import logger

parser = argparse.ArgumentParser(description='Tanuki options')
parser.add_argument('-p' , dest='port', action='store',
                    default=6768, help='Port to listen to')
parser.add_argument('--name' , dest='name', action='store',
                    default='', help='Name of the node name')
parser.add_argument('--bootstrap' , dest='bootstrap', action='store_true',
                    default=False, help='Start a new cluster')
parser.add_argument('--seeds' , dest='seeds', action='store',
                    default='', help='List of seeds nodes ip:port,ip2:port to declare to')
parser.add_argument('--tags' , dest='tags', action='store',
                    default='agent', help='List of tags for this node')
parser.add_argument('--cfg-dir' , dest='cfg_dir', action='store',
                    default='', help='Configuration files directories')
parser.add_argument('--libexec-dir' , dest='libexec_dir', action='store',
                    default='libexec', help='Check plugins directory')
parser.add_argument('--encryption' , dest='encryption_key', action='store',
                    default='', help='Encryption key')


from multiprocessing import Process
import time
import random

def f(port, name, bootstrap, seeds, tags, cfg_dir, libexec_dir):
    print 'hello', port, name, bootstrap, seeds, tags, cfg_dir, libexec_dir
    c = Cluster(int(port), name, bootstrap, seeds, tags, cfg_dir, libexec_dir)
    #node = c.get_boostrap_node()
    #c.set_alive(node, bootstrap=True)
    c.link_services()
    c.link_checks()
    c.launch_listeners()
    c.join()
    c.launch_check_thread()
    c.launch_collector_thread()
    c.launch_generator_thread()
    if 'kv' in tags.split(','):
        c.launch_replication_backlog_thread()
        c.launch_replication_first_sync_thread()
    if 'ts' in tags.split(','):
        c.start_ts_listener()

    c.main()


if __name__ == '__main__':

    START = 6768
    
    NB = 1
    
    PORTS = []
    
    for i in range(NB):
        PORTS.append(START + i)

    tags = [ ['linux,redis,kv'], ['linux,apache,redis,kv']]
    procs = []
    for i in PORTS:
        p = random.choice(PORTS)
        p2 = random.choice(PORTS)
        p3 = random.choice(PORTS)
        ts = random.choice(tags)
        _tags = ','.join(ts)
        boot = False
        if i == 6768:
            boot = True
            _tags = 'linux,kv,ts,haproxy'
        port = i
        name = ''
        seeds = '192.168.56.102:%s,192.168.56.102:%s,192.168.56.102:%s' % (p, p2, PORTS[0])

        cfg_dir = 'etc'
        libexec_dir = 'libexec'
        
        p = Process(target=f, args=(port, name, boot, seeds, _tags, cfg_dir, libexec_dir))
        p.start()
        procs.append(p)


    # Ping shinken.io during the test phase. Comment to disable this
    try:
        rq.get('http://shinken.io/ping?%s' % socket.getfqdn())
    except:
        pass


    for p in procs:
        p.join(0.1)

'''
if __name__ == '__main__':
    args = parser.parse_args()
    c = Cluster(int(args.port), args.name, args.bootstrap, args.seeds, args.tags, args.cfg_dir, args.libexec_dir)
    node = c.get_boostrap_node()
    c.set_alive(node, bootstrap=True)
    c.link_services()
    c.link_checks()
    c.launch_listeners()
    c.join()
    c.launch_check_thread()
    if 'kv' in args.tags.split(','):
        c.launch_replication_backlog_thread()
        c.launch_replication_first_sync_thread()
    if 'ts' in args.tags.split(','):
        c.start_ts_listener()

    c.main()
'''    
    
