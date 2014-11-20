#!/usr/bin/env python

# Copyright (C) 2014:
#    Gabes Jean, naparuba@gmail.com


import os
import sys
import base64
import uuid
import socket
import time
import json
import requests as rq

from kunai.log import cprint, logger
from kunai.version import VERSION


# Will be populated by the shinken CLI command
CONFIG = None



HOSTNAME = socket.gethostname()

############# ********************        MEMBERS management          ****************###########

def do_members():
    try:
        r = rq.get('http://%s:6768/agent/members' % HOSTNAME)
    except rq.exceptions.ConnectionError, exp:
        logger.error(exp)
        return
    try:
        members = json.loads(r.text).values()
    except ValueError, exp:# bad json
        logger.error('Bad return from the server %s' % exp)
        return
    members = sorted(members, key=lambda e:e['name'])
    for m in members:
        name = m['name']
        tags = m['tags']
        port = m['port']
        addr = m['addr']
        state = m['state']
        cprint('%s ' % name, end='')
        c = {'alive':'green', 'dead':'red', 'suspect':'yellow', 'leave':'cyan'}.get(state, 'cyan')
        cprint(state, color=c, end='')
        cprint(' %s:%s' % (addr, port), end='')
        cprint(' %s ' % ','.join(tags))        



def do_leave(name=''):
    # Lookup at the localhost name first
    if not name:
        try:
            r = rq.get('http://%s:6768/agent/name' % HOSTNAME)
        except rq.exceptions.ConnectionError, exp:
            logger.error(exp)
            return
        name = r.text
    try:
        r = rq.get('http://%s:6768/agent/leave/%s' % (HOSTNAME, name))
    except rq.exceptions.ConnectionError, exp:
        logger.error(exp)
        return
    if r.status_code != 200:
        logger.error('Node %s is missing' % name)
        print r.text
        return
    cprint('Node %s is set to leave state' % name,end='')
    cprint(': OK', color='green')


def do_state(name=''):
    uri = 'http://%s:6768/agent/state/%s' % (HOSTNAME, name)
    if not name:
        uri = 'http://%s:6768/agent/state' % HOSTNAME
    try:
        r = rq.get(uri)
    except rq.exceptions.ConnectionError, exp:
        logger.error(exp)
        return

    try:
        d = json.loads(r.text)
    except ValueError, exp:# bad json
        logger.error('Bad return from the server %s' % exp)
        return

    print 'Services:'
    for (sname, service) in d['services'].iteritems():
        state = service['state_id']
        cprint('\t%s ' % sname.ljust(20),end='')
        c = {0:'green', 2:'red', 1:'yellow', 3:'cyan'}.get(state, 'cyan')
        state = {0:'OK', 2:'CRITICAL', 1:'WARNING', 3:'UNKNOWN'}.get(state, 'UNKNOWN')
        cprint('%s - ' % state.ljust(8), color=c, end='')
        output = service['check']['output']
        cprint(output.strip())

    print "Checks:"
    for (cname, check) in d['checks'].iteritems():
        state = check['state_id']
        cprint('\t%s ' % cname.ljust(20),end='')
        c = {0:'green', 2:'red', 1:'yellow', 3:'cyan'}.get(state, 'cyan')
        state = {0:'OK', 2:'CRITICAL', 1:'WARNING', 3:'UNKNOWN'}.get(state, 'UNKNOWN')
        cprint('%s - ' % state.ljust(8), color=c, end='')
        output = check['output']
        cprint(output.strip())
        


def do_version():
    cprint(VERSION)


def do_join(seed=''):
    if seed == '':
        logger.error('Missing target argument. For example 192.168.0.1:6768')
        return
    try:
        r = rq.get('http://%s:6768/agent/join/%s' % (HOSTNAME, seed))
    except rq.exceptions.ConnectionError, exp:
        logger.error(exp)
        return
    try:
        b = json.loads(r.text)
    except ValueError, exp:# bad json
        logger.error('Bad return from the server %s' % exp)
        return
    cprint('Joining %s : ' % seed, end='')
    if b:
        cprint('OK', color='green')
    else:
        cprint('FAILED', color='red')



def do_keygen():
    k = uuid.uuid1().hex[:16]
    cprint('UDP Encryption key: (aka encryption_key)', end='')
    cprint(base64.b64encode(k), color='green')
    print ''
    try:
        from Crypto.PublicKey import RSA
    except ImportError:
        logger.error('Missing python-crypto module for RSA keys generation, please install it')
        return
    key = RSA.generate(2048)
    privkey = key.exportKey()
    pub_key = key.publickey()
    pubkey = pub_key.exportKey()
    print "Private RSA key (2048). (aka master_key_priv for for file mfkey.priv)"
    cprint(privkey, color='green')
    print ''
    print "Public RSA key (2048). (aka master_key_pub for file mfkey.pub)"
    cprint(pubkey, color='green')
    print ''



def do_exec(tag='*', cmd='uname -a'):
    if cmd == '':
        logger.error('Missing command')
        return
    try:
        r = rq.get('http://%s:6768/exec/%s?cmd=%s' % (HOSTNAME, tag, cmd))
    except rq.exceptions.ConnectionError, exp:
        logger.error(exp)
        return
    print r
    cid = r.text
    print "Command group launch as cid", cid
    time.sleep(5) # TODO: manage a real way to get the result..
    try:
        r = rq.get('http://%s:6768/exec-get/%s' % (HOSTNAME, cid))
    except rq.exceptions.ConnectionError, exp:
        logger.error(exp)
        return
    j = json.loads(r.text)
    print j
    res = j['res']
    for (uuid, e) in res.iteritems():
        node = e['node']
        nname = node['name']
        color = {'alive':'green', 'dead':'red', 'suspect':'yellow', 'leave':'cyan'}.get(node['state'], 'cyan')
        cprint(nname, color=color)
        cprint('Return code:', end='')
        color = {0:'green', 1:'yellow', 2:'red'}.get(e['rc'], 'cyan')
        cprint(e['rc'], color=color)
        cprint('Output:', end='')
        cprint(e['output'].strip(), color=color)
        if e['err']:
            cprint('Error:', end='')
            cprint(e['err'].strip(), color='red')
        print ''
            

exports = {
    do_members : {
        'keywords': ['members'],
        'args': [],
        'description': 'List the cluster members'
        },
    do_version : {
        'keywords': ['version'],
        'args': [],
        'description': 'Print the daemon version'
        },
    do_keygen : {
        'keywords': ['keygen'],
        'args': [],
        'description': 'Generate a encryption key'
        },
    do_exec : {
        'keywords': ['exec'],
        'args': [
            {'name' : 'tag', 'default':'', 'description':'Name of the node tag to execute command on'},
            {'name' : 'cmd', 'default':'uname -a', 'description':'Command to run on the nodes'},
            ],
        'description': 'Execute a command (default to uname -a) on a group of node of the good tag (default to all)'
        },

    do_join : {
        'keywords': ['join'],
        'description': 'Join another node cluster',
        'args': [
            {'name' : 'seed', 'default':'', 'description':'Other node to join. For example 192.168.0.1:6768'},
            ],
        },

    do_leave : {
        'keywords': ['leave'],
        'description': 'Join another node cluster',
        'args': [
            {'name' : 'name', 'default':'', 'description':'Name of the node to force leave. If void, leave our local node'},
            ],
        },


    do_state : {
        'keywords': ['state'],
        'description': 'Print the state of a node',
        'args': [
            {'name' : 'name', 'default':'', 'description':'Name of the node to print state. If void, take our localhost one'},
            ],
        },


    }
