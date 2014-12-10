import os
import sys
import socket
import json
import uuid
import imp
import threading
import argparse
import time
import random
import math
import shutil
import hashlib
import signal
import traceback
import cStringIO
import bisect
import requests as rq
import shlex
import subprocess
import tempfile
import tarfile
import base64
import shutil
import glob
import zlib
import re
import copy
import cPickle

try:
    from Crypto.Cipher import AES
    from Crypto.PublicKey import RSA
except ImportError:
    AES = None
    RSA = None

# DO NOT FORGEET:
# sysctl -w net.core.rmem_max=26214400

from kunai.bottle import route, run, request, abort, error, redirect, response
import kunai.bottle as bottle
bottle.debug(True)

from kunai.log import logger
from kunai.kv import KVBackend
from kunai.dnsquery import DNSQuery
from kunai.ts import TSListener
from kunai.wsocket import WebSocketBackend
from kunai.util import make_dir, copy_dir
from kunai.threadmgr import threader
from kunai.perfdata import PerfDatas
from kunai.now import NOW
from kunai.collector import Collector

KGOSSIP = 10

REPLICATS = 1

#LIMIT= 4 * math.ceil(math.log10(float(2 + 1)))



class EnableCors(object):
    name = 'enable_cors'
    api = 2

    def apply(self, fn, context):
        def _enable_cors(*args, **kwargs):
            # set CORS headers
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS, DELETE, PATCH'
            response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, X-Shinken-Token'
            response.headers['Access-Control-Allow-Crendentials'] = 'true'
            if bottle.request.method != 'OPTIONS':
                # actual request; reply with the actual response
                return fn(*args, **kwargs)

        return _enable_cors



class Cluster(object):
    
    parameters = {'port': {'type':'int', 'mapto':'port'},
                  'data': {'type':'path', 'mapto':'data_dir'},
                  'libexec': {'type':'path', 'mapto':'libexec_dir'},
                  'bootstrap': {'type':'bool', 'mapto':'bootstrap'},
                  'seeds': {'type':'list', 'mapto':'seeds'},
                  'tags': {'type':'list', 'mapto':'tags'},
                  'encryption_key': {'type':'string', 'mapto':'encryption_key'},
                  'master_key_priv': {'type':'string', 'mapto':'master_key_priv'},
                  'master_key_pub': {'type':'string', 'mapto':'master_key_pub'},
                  }


    def __init__(self, port, name, bootstrap, seeds, tags, cfg_dir, libexec_dir):
        self.set_exit_handler()

        # Launch the now-update thread
        NOW.launch()
        
        # This will be the place where we will get our configuration data
        self.cfg_data = {}
        
        self.checks = {}
        self.services = {}
        # keep a list of the checks names that match our tags
        self.active_checks = []
        
        # Some default value that can be erased by the
        # main configuration file
        # By default no encryption
        self.encryption_key = ''
        # Same for public/priv for the master fucking key
        self.master_key_priv = '' # Paths
        self.master_key_pub = ''
        self.mfkey_priv = None # real key objects
        self.mfkey_pub  = None
        
        self.port = port
        self.name = name
        if not self.name:
            self.name = '%s-%s' % (socket.gethostname(), self.port)
        self.tags = [s.strip() for s in tags.split(',') if s.strip()]
        self.interrupted = False
        self.bootstrap = bootstrap
        self.seeds = [s.strip() for s in seeds.split(',')]
        
        # list of uuid to ping back because we though they were dead        
        self.to_ping_back = [] 
        
        # By defautl, we are alive :)
        self.state = 'alive'
        self.addr = socket.gethostname()#'0.0.0.0'
        self.broadcasts = []
        self.data_dir = os.path.abspath('data/data-%s' % self.name)
        
        # Now look at the cfg_dir part
        self.cfg_dir = cfg_dir
        if cfg_dir:
           self.cfg_dir = os.path.abspath(self.cfg_dir)
           self.load_cfg_dir()        
        
        # We can start with a void data dir
        if not os.path.exists(self.data_dir):
            os.mkdir(self.data_dir)
        
        # open the log file
        logger.load(self.data_dir, self.name)

        # Look if our encryption key is valid or not
        if self.encryption_key:
            if AES is None:
                logger.error('You set an encryption key but cannot import python-crypto module, please install it. Exiting.')
                sys.exit(2)
            try:
                self.encryption_key = base64.b64decode(self.encryption_key)
            except ValueError:
                logger.warning('The encryption key is invalid, not in base64 format')
                # todo: exit or no exit?

        # Same for master fucking key PRIVATE
        if self.master_key_priv:
            if not os.path.isabs(self.master_key_priv):
                self.master_key_priv = os.path.join(self.cfg_dir, self.master_key_priv)
            if not os.path.exists(self.master_key_priv):
                logger.error('Cannot find the master key private file at %s' % self.master_key_priv)
            if RSA is None:
                logger.error('You set a master private key but but cannot import python-crypto module, please install it. Exiting.')
                sys.exit(2)
            buf = ''
            with open(self.master_key_priv, 'r') as f:
                buf = f.read()
            try:
                self.mfkey_priv = RSA.importKey(buf)
            except Exception, exp:
                logger.error('Invalid master private key at %s. Exiting.' % self.master_key_priv)
                sys.exit(2)
            if not self.mfkey_priv.has_private():
                logger.error('Invalid master private key at %s. Not a private key. Exiting.' % self.master_key_priv)
                sys.exit(2)
            logger.info('Master private key file %s is loaded' % self.master_key_priv)
        
        # Same for master fucking key PUBLIC
        if self.master_key_pub:
            if not os.path.isabs(self.master_key_pub):
                self.master_key_pub = os.path.join(self.cfg_dir, self.master_key_pub)
            if not os.path.exists(self.master_key_pub):
                logger.error('Cannot find the master key public file at %s' % self.master_key_pub)
            if RSA is None:
                logger.error('You set a master public key but but cannot import python-crypto module, please install it. Exiting.')
                sys.exit(2)
            buf = ''
            with open(self.master_key_pub, 'r') as f:
                buf = f.read()
            try:
                self.mfkey_pub = RSA.importKey(buf)
            except Exception, exp:
                logger.error('Invalid master public key at %s. Exiting.' % self.master_key_pub)
                sys.exit(2)        
            logger.info('Master public key file %s is loaded' % self.master_key_pub)

        # Open the retention data about our pevious runs
        self.incarnation_file = os.path.join(self.data_dir, 'incarnation')
        self.server_key_file = os.path.join(self.data_dir, 'server.key')
        self.nodes_file = os.path.join(self.data_dir, 'nodes.json')
        self.check_retention = os.path.join(self.data_dir, 'checks.dat')
        self.service_retention = os.path.join(self.data_dir, 'services.dat')
        self.last_alive_file = os.path.join(self.data_dir, 'last_alive')
        
        # Our cluster need a uniq uuid
        self.uuid = ''
        if os.path.exists(self.server_key_file):
            with open(self.server_key_file, 'r') as f:
                self.uuid = f.read()
            logger.log("KEY: %s loaded from the server file %s" % (self.uuid, self.server_key_file))
        else:
            self.uuid = hashlib.sha1(uuid.uuid1().get_hex()).hexdigest()
            # now save the key
            with open(self.server_key_file, 'w') as f:
                f.write(self.uuid)
            logger.log("KEY: %s saved to the server file %s" % (self.uuid, self.server_key_file))

        # Now load nodes to do not start from zero
        if os.path.exists(self.nodes_file):
            with open(self.nodes_file, 'r') as f:
                self.nodes = json.loads(f.read())
        else:
            self.nodes = {}
        # We must protect the nodes with a lock
        self.nodes_lock = threading.RLock()
        
        # Load some files, like the old incarnation file
        if os.path.exists(self.incarnation_file):
            with open(self.incarnation_file, 'r') as f:
                self.incarnation = json.loads(f.read())
                self.incarnation += 1
        else:
            self.incarnation = 0

        self.load_check_retention()
        self.load_service_retention()

        # Now the kv backend
        self.kv = KVBackend(self.data_dir)
        
        self.replication_backlog_lock = threading.RLock()
        self.replication_backlog = {}
        
        self.last_retention_write = time.time()
        
        if os.path.exists(self.last_alive_file):
            with open(self.last_alive_file, 'r') as f:
                self.last_alive = json.loads(f.read())
        else:
            self.last_alive = int(time.time())
            
        # Try to clean libexec and configuration directories
        self.libexec_dir = libexec_dir
        if self.libexec_dir:
            self.libexec_dir = os.path.abspath(self.libexec_dir)
            
        self.configuration_dir = cfg_dir
        if self.configuration_dir:
            self.configuration_dir = os.path.abspath(self.configuration_dir)
        
        # Our main events dict, should not be too old or we will delete them
        self.events_lock = threading.RLock()
        self.events = {}
        self.max_event_age = 30
        
        # We will receive a list of path to update for libexec, and we will manage them
        # in athread so the upd thread is not blocking
        self.libexec_to_update = []
        self.configuration_to_update = []
        self.launch_update_libexec_cfg_thread()

        print "LOADED CFG DATA", self.cfg_data

        # by defualt do not launch timeserie listeners
        self.ts = None

        # Now no websocket
        self.webso = None

        # Compile the macro patern once
        self.macro_pat = re.compile(r'(\$ *(.*?) *\$)+')

        self.put_key_buffer = []
        # Launch a thread that will reap all put key asked by the udp
        self.put_key_reaper_thread = threader.create_and_launch(self.put_key_reaper, name='put-key-reaper')

        # Execs launch as threads
        self.execs = {}
        # Challenge send so we can match the response when we will get them
        self.challenges = {}

        # Load all collectors
        self.collectors = {}
        self.load_collectors()


    def load_cfg_dir(self):
       if not os.path.exists(self.cfg_dir):
          logger.log('ERROR: the configuration directory %s is missing' % self.cfg_dir)
          sys.exit(2)
       for root, dirs, files in os.walk(self.cfg_dir):
          for name in files:
             if name.endswith('.json'):
                fp = os.path.join(root, name)
                self.open_cfg_file(fp)


    def open_cfg_file(self, fp):
       o = {}
       with open(fp, 'r') as f:
          buf = f.read()
          try:
             o = json.loads(buf)
          except Exception, exp:
             logger.log('ERROR: the configuration file %s malformed: %s' % (fp, exp))
             sys.exit(2)
       if not isinstance(o, dict):
             logger.log('ERROR: the configuration file %s content is not a valid dict' % fp)
             sys.exit(2)
       logger.debug("Configuration, opening file data", o)
       if 'check' in o:
          check = o['check']
          if not isinstance(check, dict):
             logger.log('ERROR: the check from the file %s is not a valid dict' % fp)
             sys.exit(2)
          print fp
          fname = fp[len(self.cfg_dir)+1:]
          print "FNAME", fname
          mod_time = int(os.path.getmtime(fp))
          cname = os.path.splitext(fname)[0]
          self.import_check(check, 'file:%s' % fname, cname, mod_time=mod_time)

       elif 'service' in o:
          service = o['service']
          if not isinstance(service, dict):
             logger.log('ERROR: the service from the file %s is not a valid dict' % fp)
             sys.exit(2)

          mod_time = int(os.path.getmtime(fp))
          fname = fp[len(self.cfg_dir)+1:]
          sname = os.path.splitext(fname)[0]
          self.import_service(service, 'file:%s' % fname, sname, mod_time=mod_time)
       else: # classic main file
           # grok all others data so we can use them in our checks
           parameters = self.__class__.parameters
           for (k,v) in o.iteritems():
               # if k is not a internal parameters, use it in the cfg_data part
               if k not in ['check', 'service'] and not k in parameters:
                   self.cfg_data[k] = v
               else: # cannot be check and service here
                   e = parameters[k]
                   _type = e['type']
                   mapto = e['mapto']
                   if _type == 'int':
                       try:
                           int(v)
                       except ValueError:
                           logger.error('The parameter %s is not an int' % k)
                           return
                   elif _type in ['path', 'string']:
                       if not isinstance(v, basestring):
                           logger.error('The parameter %s is not a string' % k)
                           return
                   elif _type == 'bool':
                       if not isinstance(v, bool):
                           logger.error('The parameter %s is not a bool' % k)
                           return
                   elif _type == 'list':
                       if not isinstance(v, list):
                           logger.error('The parameter %s is not a list' % k)
                           return
                   else:
                       logger.error('Unkown parameter type %s' % k)
                       return
                   # It's valid, I set it :)
                   setattr(self, mapto, v)
                           
                   


    def load_check_retention(self):
       if not os.path.exists(self.check_retention):
          return

       logger.log('CHECK loading check retention file %s' % self.check_retention)
       with open(self.check_retention, 'r') as f:
          loaded = json.loads(f.read())
          for (cid, c) in loaded.iteritems():
             if cid in self.checks:
                print "C", c
                check = self.checks[cid]
                to_load = ['last_check', 'output', 'state', 'state_id']
                for prop in to_load:
                   check[prop] = c[prop]
       logger.log('CHECK loaded %s' % self.checks)

    
    def load_service_retention(self):
       if not os.path.exists(self.service_retention):
          return
       
       logger.log('CHECK loading service retention file %s' % self.service_retention)
       with open(self.service_retention, 'r') as f:
          loaded = json.loads(f.read())
          for (cid, c) in loaded.iteritems():
             if cid in self.services:
                service = self.services[cid]
                to_load = ['state_id', 'incarnation']
                for prop in to_load:
                   service[prop] = c[prop]
       logger.log('CHECK loaded %s' % self.services)


    # Load and sanatize a check object in our configuration
    def import_check(self, check, fr, name, mod_time=0, service=''):
       check['from'] = fr
       check['id'] = check['name'] = name
       
       if not 'interval' in check:
          check['interval'] = '10s'
       if not 'script' in check:
          check['script'] = ''
       if not 'last_check' in check:
          check['last_check'] = 0
       if not 'notes' in check:
          check['notes'] = ''
       if service:
          check['service'] = service
       if not 'apply_on' in check:
          # we take the basename of this check directory forthe apply_on
          # and if /, take *  (aka means all)
          apply_on = os.path.basename(os.path.dirname(name))
          if not apply_on:
             apply_on = '*'
          check['apply_on'] = apply_on
          print "APPLY ON", apply_on
       check['modification_time'] = mod_time
       check['state'] = 'pending'
       check['state_id'] = 3
       check['output'] = ''
       self.checks[check['id']] = check


    # We have a new check from the HTTP, save it where it need to be
    def delete_check(self, cname):
        p = os.path.normpath(os.path.join(self.cfg_dir, cname+'.json'))
        if not p.startswith(self.cfg_dir):
            raise Exception("Bad file path for your script, won't be in the cfg directory tree")
        # clean on disk
        if os.path.exists(p):
            os.unlink(p)
        # Now clean in memory too
        if cname in self.checks:
            del self.checks[cname]
        self.link_checks()

    
    # We have a new check from the HTTP, save it where it need to be
    def save_check(self, cname, check):        
        p = os.path.normpath(os.path.join(self.cfg_dir, cname+'.json'))
        if not p.startswith(self.cfg_dir):
            raise Exception("Bad file path for your script, won't be in the cfg directory tree")

        # Look if the file directory exists or if not cannot be created
        p_dir = os.path.dirname(p)
        if not os.path.exists(p_dir):
            os.makedirs(p_dir)

        # import a copy, so we dont mess with the fieldsweneed to save
        to_import = copy.copy(check)
        # Now importit in our running part
        self.import_check(to_import, 'from:http', cname)
        # and put the new one in the active running checks, maybe
        self.link_checks()

        # Now we can save the received entry, but first clean unless props
        to_remove = ['from', 'last_check', 'modification_time', 'state', 'output', 'state_id', 'id']
        for prop in to_remove:
            try:
                del check[prop]
            except KeyError:
                pass
                    
        o = {'check':check}
        logger.debug('HTTP check saving the object %s into the file %s' % (o, p), part='http')
        buf = json.dumps(o , sort_keys=True, indent=4)
        tempdir = tempfile.mkdtemp()
        f = open(os.path.join(tempdir, 'temp.json'), 'w')
        f.write(buf)
        f.close()
        shutil.move(os.path.join(tempdir, 'temp.json'), p)
        shutil.rmtree(tempdir)


    def import_service(self, service, fr, sname, mod_time=0):
       service['from'] = fr
       service['name'] = service['id'] = sname
       if not 'notes' in service:
          service['notes'] = ''
       if not 'apply_on' in service:
          # we take the basename of this check directory forthe apply_on
          # and if /, take the service name
          apply_on = os.path.basename(os.path.dirname(sname))
          if not apply_on:
             apply_on = service['name']
          service['apply_on'] = service['name']
          print "APPLY SERVICE ON", apply_on

       if 'check' in service:
          check = service['check']
          cname = 'service:%s' % sname
          # for the same apply_on of the check as ourself
          check['apply_on'] = apply_on
          self.import_check(check, fr, cname, mod_time=mod_time, service=service['id'])
          
       # Put the default state to unknown, retention will load
       # the old data
       service['state_id'] = 3
       service['modification_time'] = mod_time
       service['incarnation'] = 0
       
       # Add it into the services list
       self.services[service['id']] = service



    # We have a new service from the HTTP, save it where it need to be
    def save_service(self, sname, service):        
        p = os.path.normpath(os.path.join(self.cfg_dir, sname+'.json'))
        if not p.startswith(self.cfg_dir):
            raise Exception("Bad file path for your script, won't be in the cfg directory tree")

        # Look if the file directory exists or if not cannot be created
        p_dir = os.path.dirname(p)
        if not os.path.exists(p_dir):
            os.makedirs(p_dir)

        # import a copy, so we dont mess with the fieldsweneed to save
        to_import = copy.copy(service)
        # Now importit in our running part
        self.import_service(to_import, 'from:http', sname)
        # and put the new one in the active running checks, maybe
        self.link_services()

        # We maybe got a new service, so export this data to every one in the gossip way :)
        node = self.nodes[self.uuid]
        self.incarnation += 1
        node['incarnation'] = self.incarnation
        self.stack_alive_broadcast(node)
        
        # Now we can save the received entry, but first clean unless props
        to_remove = ['from', 'last_check', 'modification_time', 'state', 'output', 'state_id', 'id']
        for prop in to_remove:
            try:
                del service[prop]
            except KeyError:
                pass
        
        o = {'service':service}
        logger.debug('HTTP service saving the object %s into the file %s' % (o, p), part='http')
        buf = json.dumps(o , sort_keys=True, indent=4)
        tempdir = tempfile.mkdtemp()
        f = open(os.path.join(tempdir, 'temp.json'), 'w')
        f.write(buf)
        f.close()
        shutil.move(os.path.join(tempdir, 'temp.json'), p)
        shutil.rmtree(tempdir)


    # We have a new check from the HTTP, save it where it need to be
    def delete_service(self, sname):
        p = os.path.normpath(os.path.join(self.cfg_dir, sname+'.json'))
        if not p.startswith(self.cfg_dir):
            raise Exception("Bad file path for your script, won't be in the cfg directory tree")
        # clean on disk
        if os.path.exists(p):
            os.unlink(p)
        # Now clean in memory too
        if sname in self.services:
            del self.services[sname]
        self.link_services()
        # We maybe got a less service, so export this data to every one in the gossip way :)
        node = self.nodes[self.uuid]
        self.incarnation += 1
        node['incarnation'] = self.incarnation
        self.stack_alive_broadcast(node)


       
    # Look at our services dict and link the one we are apply_on
    # so the other nodes are aware about our tags/service
    def link_services(self):
        logger.debug('LINK my services and my node entry')
        node = self.nodes[self.uuid]
        tags = node['tags']
        for (sname, service) in self.services.iteritems():
            logger.debug('LINK %s on ==> %s' % (service, tags))
            apply_on = service.get('apply_on', '')
            logger.debug('LINK apply on %s' % apply_on)
            if apply_on and apply_on in tags:
                logger.debug('LINK activate service %s' % sname)
                node['services'][sname] = service


    # For checks we will only populate our active_checks list
    # with the name of the checks we are apply_on about
    def link_checks(self):
       logger.debug('LOOKING FOR our checks that match our tags')
       node = self.nodes[self.uuid]
       tags = node['tags']
       active_checks = []
       for (cname, check) in self.checks.iteritems():
          apply_on = check.get('apply_on', '*')
          logger.debug('LINK check apply on %s' % apply_on)
          if apply_on == '*' or apply_on in tags:
             logger.debug('LINK activate checke %s' % cname)
             active_checks.append(cname)
       self.active_checks = active_checks
       # Also update our checks list in KV space
       self.update_checks_kv()


    def load_collector(self, cls):
        colname = cls.__name__.lower()
        logger.debug('Loading collector %s from class %s' % (colname, cls))
        try:
            inst = cls(self.cfg_data)
        except Exception, exp:
            
            logger.error('Cannot load the %s collector: %s' % (cls, traceback.format_exc()))
            return
        e = {
            'name': colname,
            'inst': inst,
            'last_check': 0,
            'next_check': int(time.time()) + int(random.random())*10,
            }
        self.collectors[cls] = e


    def load_collectors(self):
        collector_dir = os.path.join(self.data_dir, 'collectors')
        p = collector_dir+'/*py'
        print "LOAD", p
        collector_files = glob.glob(p)
        print "LOADING COLLECTOR FILES", collector_files, collector_dir
        for f in collector_files:
            fname = os.path.splitext(os.path.basename(f))[0]
            try:
                m = imp.load_source('collector%s' % fname, f)
            except Exception, exp:
                print "COLLECTOR LOAD FAIL", exp
                continue
            print "LOADED COLLECTOR", m
            print m.__dict__
            for (k,v) in m.__dict__.iteritems():
                print k, v

        collector_clss = Collector.get_sub_class()
        for ccls in collector_clss:
            # skip base module Collector
            if ccls == Collector:
                continue
            # Maybe this collector is already loaded
            if ccls in self.collectors:
                continue
            self.load_collector(ccls)


    # What to do when we receive a signal from the system
    def manage_signal(self, sig, frame):
        logger.log("I'm process %d and I received signal %s" % (os.getpid(), str(sig)))
        if sig == signal.SIGUSR1:  # if USR1, ask a memory dump
            logger.log('MANAGE USR1')
        elif sig == signal.SIGUSR2: # if USR2, ask objects dump
            logger.log('MANAGE USR2')
        else:  # Ok, really ask us to die :)
            self.interrupted = True


    def set_exit_handler(self):
        func = self.manage_signal
        if os.name == "nt":
            try:
                import win32api
                win32api.SetConsoleCtrlHandler(func, True)
            except ImportError:
                version = ".".join(map(str, sys.version_info[:2]))
                raise Exception("pywin32 not installed for Python " + version)
        else:
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGUSR1, signal.SIGUSR2):
                signal.signal(sig, func)
        

    def log(self, *args):
       logger.log(args)

    
    # We received data from UDP, if we are set to encrypt, decrypt it
    def decrypt(self, data):
        if not self.encryption_key:
            return data
        logger.debug('DECRYPT with '+self.encryption_key)
        # Be sure the data is x16 lenght
        if len(data) % 16 != 0:
            data += ' ' * (-len(data) % 16)
        try:
            cyph = AES.new(self.encryption_key, AES.MODE_ECB)
            ndata = cyph.decrypt(data).strip()
            return ndata
        except Exception, exp:
            logger.error('Decryption fail:', exp, part='gossip')
            return ''

        
    def encrypt(self, data):
        if not self.encryption_key:
            return data
        logger.debug('ENCRYPT with '+self.encryption_key)
        # Be sure the data is x16 lenght
        if len(data) % 16 != 0:
            data += ' ' * (-len(data) % 16)
        try:
            cyph = AES.new(self.encryption_key, AES.MODE_ECB)
            ndata = cyph.encrypt(data)
            return ndata
        except Exception, exp:
            logger.error('Encryption fail:', exp, part='gossip')
            return ''
        


    def launch_check_thread(self):
       self.check_thread = threader.create_and_launch(self.do_check_thread, name='check-thread')


    def launch_collector_thread(self):
        self.collector_thread = threader.create_and_launch(self.do_collector_thread, name='collector-thread')


    def launch_replication_backlog_thread(self):
       self.replication_backlog_thread = threader.create_and_launch(self.do_replication_backlog_thread, name='replication-backlog-thread')


    def launch_replication_first_sync_thread(self):
       self.replication_first_sync_thread = threader.create_and_launch(self.do_replication_first_sync_thread, name='replication-first-sync-thread')


    def launch_listeners(self):
        self.udp_thread = threader.create_and_launch(self.launch_udp_listener, name='udp-thread')
        self.tcp_thread = threader.create_and_launch(self.launch_tcp_listener, name='tcp-thread')
        self.webso_thread = threader.create_and_launch(self.launch_websocket_listener, name='websocket-thread')
        self.dns_thread = threader.create_and_launch(self.launch_dns_listener, name='dns-thread')


    def launch_udp_listener(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
        self.udp_sock.bind((self.addr, self.port))
        logger.log("UDP port open", self.port, part='udp')
        while not self.interrupted:
            data, addr = self.udp_sock.recvfrom(65535) # buffer size is 1024 bytes

            # No data? bail out :)
            if len(data) == 0:
                continue

            # Look if we use encryption
            data = self.decrypt(data)
            # Maybe the decryption failed?
            if data == '':
                continue
            logger.debug("UDP: received message:", data, addr, part='udp')
            # Ok now we should have a json to parse :)
            try:
                raw = json.loads(data)
            except ValueError:# garbage
                continue
            messages = []
            if isinstance(raw, list):
                messages = raw
            else:
                messages = [raw]
            for m in messages:
                t = m['type']
                if t == 'ping':
                    ack = {'type':'ack', 'seqno':m['seqno']}
                    ret_msg = json.dumps(ack)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
                    enc_ret_msg = self.encrypt(ret_msg)
                    sock.sendto(enc_ret_msg, addr)
                    sock.close()
                    logger.debug("PING RETURN ACK MESSAGE", ret_msg, part='gossip')
                    # now maybe the source was a suspect that just ping me? if so
                    # ask for a future ping
                    fr_uuid = m['from']
                    node = self.nodes.get(fr_uuid, None)
                    if node and node['state'] != 'alive':
                        logger.debug('PINGBACK +ing node', node['name'], part='gossip')
                        self.to_ping_back.append(fr_uuid)
                elif t == 'ping-relay':
                    tgt = m.get('tgt')
                    _from = m.get('from', '')
                    if not tgt or not _from:
                        continue
                    # We are ask to do a indirect ping to tgt and return the ack to
                    # _from, do this in a thread so we don't lock here
                    def do_indirect_ping(self, tgt, _from, addr):
                        logger.debug('do_indirect_ping', tgt, _from, part='gossip')
                        ntgt = self.nodes.get(tgt, None)
                        nfrom = self.nodes.get(_from, None)
                        # If the dest or the from node are now unknown, exit this thread
                        if not ntgt or not nfrom:
                            return
                        # Now do the real ping
                        ping_payload = {'type':'ping', 'seqno':0, 'node': ntgt['name'], 'from': self.uuid}
                        message = json.dumps(ping_payload)
                        tgtaddr = ntgt['addr']
                        tgtport = ntgt['port']
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
                            enc_message = self.encrypt(message)
                            sock.sendto(enc_message, (tgtaddr, tgtport) )
                            logger.debug('PING waiting %s ack message from a ping-relay' % ntgt['name'], part='gossip')
                            # Allow 3s to get an answer
                            sock.settimeout(3)
                            ret = sock.recv(65535)
                            logger.debug('PING (relay) got a return from %s' %  ntgt['name'], ret, part='gossip')
                            # An aswer? great it is alive! Let it know our _from node
                            ack = {'type':'ack', 'seqno':0}
                            ret_msg = json.dumps(ack)
                            enc_ret_msg = self.encrypt(ret_msg)
                            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
                            sock.sendto(enc_ret_msg, addr)
                            sock.close()
                        except socket.timeout, exp:
                            # cannot reach even us? so it's really dead, let the timeout do its job on _from
                            pass
                    # Do the indirect ping as a sub-thread
                    threader.create_and_launch(do_indirect_ping, name='indirect-ping-%s-%s' % (tgt, _from), args=(self, tgt, _from, addr))
                elif t == '/kv/put':
                    k = m['k']
                    v = m['v']
                    fw = m.get('fw', False)
                    # For perf data we allow the udp send
                    self.put_key(k,v, allow_udp=True, fw=fw)
                elif t == '/ts/new':
                    key = m.get('key', '')
                    # Skip this message for classic nodes
                    if self.ts is None or key == '':
                        continue
                    # if TS do not have it, it will propagate it
                    self.ts.set_name_if_unset(key)
                # Someone is asking us a challenge, ok do it
                elif t == '/exec/challenge/ask':
                    # If we don't have the public key, bailing out now
                    if self.mfkey_pub is None:
                        logger.debug('EXEC skipping exec call becaue we do not have a public key', part='exec')
                        continue
                    cid = uuid.uuid1().get_hex() # challgenge id
                    challenge = uuid.uuid1().get_hex()
                    e = {'ctime':int(time.time()), 'challenge':challenge}
                    self.challenges[cid] = e
                    # return a tuple with only the first element useful (str)                    
                    _c = self.mfkey_pub.encrypt(challenge, 0)[0] # encrypt 0=dummy param not used
                    echallenge = base64.b64encode(_c) 
                    ping_payload = {'type':'/exec/challenge/proposal', 'fr': self.uuid, 'challenge':echallenge, 'cid':cid}
                    message = json.dumps(ping_payload)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
                    enc_message = self.encrypt(message)
                    logger.debug('EXEC asking us a challenge, return %s(%s) to %s' % (challenge, echallenge, addr), part='exec')
                    sock.sendto(enc_message, addr)
                    sock.close()
                elif t == '/exec/challenge/return':
                    # Don't even look at it if we do not have a public key....
                    if self.mfkey_pub is None:
                        continue
                    cid = m.get('cid', '')
                    response64 = m.get('response', '')
                    cmd = m.get('cmd', '')
                    _from = m.get('fr', '')
                    # skip invalid packets
                    if not cid or not response64 or not cmd:
                        continue
                    # Maybe we got a bad or old challenge response...
                    p = self.challenges.get(cid, None)
                    if not p:
                        continue
                    
                    try:
                        response = base64.b64decode(response64)
                    except ValueError:
                        logger.debug('EXEC invalid base64 response from %s' % addr, part='exec')
                        continue
                    
                    logger.debug('EXEC got a challenge return from %s for %s:%s' % (_from, cid, response), part='exec')
                    # now try to decrypt the response of the other
                    # This function take a tuple of size=2, but only look at the first...
                    if response == p['challenge']:
                        logger.debug('EXEC GOT GOOD FROM A CHALLENGE, DECRYPTED DATA', cid, response, p['challenge'], response==p['challenge'], part='exec')
                        threader.create_and_launch(self.do_launch_exec, name='do-launch-exec-%s' % cid, args=(cid, cmd, addr))
                else:
                    self.manage_message(m)


    def launch_dns_listener(self):
       sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
       logger.debug('DNS launched server port %d' % (self.port + 3000), part='dns')
       sock.bind(('', self.port + 3000 ))
       while not self.interrupted:
          data, addr = sock.recvfrom(1024)
          try:
             p = DNSQuery(data)
             r = p.lookup_for_nodes(self.nodes)
             logger.debug("DNS lookup nodes response:", r, part='dns')
             sock.sendto(p.response(r), addr)
          except Exception, exp:
             logger.log("DNS problem", exp, part='dns')


    def launch_websocket_listener(self):
        self.webso = WebSocketBackend(self)
        self.webso.run()


    def forward_to_websocket(self, msg):
        if self.webso:
            self.webso.send_all(msg)


    # TODO: SPLIT into modules :)
    def launch_tcp_listener(self):
        @error(404)
        def err404(error):
           return ''

        
        @route('/')
        def slash():
            return 'OK'
        
        @route('/agent/name')
        def get_name():
            return self.nodes[self.uuid]['name']


        @route('/agent/state/:nname')
        @route('/agent/state')
        def get_state(nname=''):
            response.content_type = 'application/json'
            r = {'checks':{}, 'services':{}}
            # by default it's us
            # maybe its us, maybe not
            if nname == '':
                for (cid, check) in self.checks.iteritems():
                    # maybe this chck is not a activated one for us, if so, bail out
                    if not cid in self.active_checks:
                        continue
                    r['checks'][cid] = check
                r['services'] = self.nodes[self.uuid]['services']
                return r
            else: # find the elements
                node = None
                with self.nodes_lock:
                    for n in self.nodes.values():
                        if n['name'] == nname:
                            node = n
                if node is None:
                    return abort(404, 'This node is not found')
                # Services are easy, we alrady got them
                r['services'] = node['services']
                # checks are harder, we must find them in the kv nodes
                v = self.get_key('__health/%s' % nname)
                if v is None:
                    logger.debug('Cannot access to the checks list for', nname, part='http')
                    return r
                lst = json.loads(v)
                for cid in lst:
                    v = self.get_key('__health/%s/%s' % (nname, cid))
                    if v is None: # missing check entry? not a real problem
                        continue
                    check = json.loads(v)
                    r['checks'][cid] = check
                return r

        
        @route('/agent/leave/:nname')
        def set_node_leave(nname):
            node = None
            with self.nodes_lock:
                for n in self.nodes.values():
                    if n['name'] == nname:
                        node = n
            if node is None:
                return abort(404, 'This node is not found')
            logger.log('PUTTING LEAVE the node %s' % n, part='http')
            self.set_leave(node)
            return
        
        
        @route('/push-pull')
        def interface_push_pull():
           response.content_type = 'application/json'
           logger.debug("PUSH-PULL called by HTTP", part='gossip')
           data = request.GET.get('msg')
           
           msg = json.loads(data)
           
           self.manage_message(msg)
           nodes = {}
           with self.nodes_lock:
               nodes = copy.copy(self.nodes)
           m = {'type': 'push-pull-msg', 'nodes': nodes}

           logger.debug("PUSH-PULL returning my own nodes", part='gossip')
           return m


        # We want a state of all our services, with the members
        @route('/state/services')
        def state_services():
           response.content_type = 'application/json'
           logger.debug("/state/services is called", part='http')
           # We don't want to modify our services objects
           services = copy.deepcopy(self.services)
           for service in services.values():
               service['members'] = []
               service['passing-members'] = []
               service['passing'] = 0
               service['failing-members'] = []
               service['failing'] = 0
           with self.nodes_lock:
               for (uuid, node) in self.nodes.iteritems():
                   for (sname, service) in node['services'].iteritems():
                       if sname not in services:
                           continue
                       services[sname]['members'].append(node['name'])
                       if service['state_id'] == 0:
                           services[sname]['passing'] += 1
                           services[sname]['passing-members'].append(node['name'])
                       else:
                           services[sname]['failing'] += 1
                           services[sname]['failing-members'].append(node['name'])
           
           return services


        @route('/agent/checks')
        def agent_checks():
           response.content_type = 'application/json'
           logger.debug("/agent/checks is called", part='http')
           return self.checks


        @route('/agent/checks/:cname#.+#')
        def agent_check(cname):
            response.content_type = 'application/json'
            logger.debug("/agent/checks is called for %s" % cname, part='http')
            if not cname in self.checks:
                return abort(404, 'check not found')
            return self.checks[cname]


        @route('/agent/checks/:cname#.+#', method='DELETE')
        def agent_DELETE_check(cname):
            logger.debug("/agent/checks DELETE is called for %s" % cname, part='http')
            if not cname in self.checks:
                return
            self.delete_check(cname)
            return


        @route('/agent/checks/:cname#.+#', method='PUT')
        def interface_PUT_agent_check(cname):
           value = request.body.getvalue()
           logger.debug("HTTP: PUT a new/change check %s (value:%s)" % (cname, value), part='http')
           try:
               check = json.loads(value)
           except ValueError: # bad json
               return abort(400, 'Bad json entry')
           logger.debug("HTTP: PUT a new/change check %s (value:%s)" % (cname, check), part='http')
           self.save_check(cname, check)           
           return


        @route('/agent/services')
        def agent_services():
            response.content_type = 'application/json'
            logger.debug("/agent/services is called", part='http')
            return self.services


        @route('/agent/services/:sname#.+#')
        def agent_service(sname):
            response.content_type = 'application/json'
            logger.debug("/agent/service is called for %s" % sname, part='http')
            if not sname in self.services:
                return abort(404, 'service not found')
            return self.services[sname]


        @route('/agent/services/:sname#.+#', method='PUT')
        def interface_PUT_agent_service(sname):
           value = request.body.getvalue()
           logger.debug("HTTP: PUT a new/change service %s (value:%s)" % (sname, value), part='http')
           try:
               service = json.loads(value)
           except ValueError: # bad json
               return abort(400, 'Bad json entry')
           logger.debug("HTTP: PUT a new/change check %s (value:%s)" % (sname, service), part='http')
           self.save_service(sname, service)
           return


        @route('/agent/services/:sname#.+#', method='DELETE')
        def agent_DELETE_service(sname):
           logger.debug("/agent/service DELETE is called for %s" % sname, part='http')
           if not sname in self.services:
              return
           self.delete_service(sname)
           return


        @route('/agent/members')
        def agent_members():
            response.content_type = 'application/json'
            logger.debug("/agent/members is called", part='http')
            nodes = {}
            with self.nodes_lock:
                nodes = copy.copy(self.nodes)
            return nodes


        @route('/kv/:ukey#.+#', method='GET')
        def interface_GET_key(ukey):
           t0 = time.time()
           logger.debug("GET KEY %s" % ukey, part='kv')
           v = self.get_key(ukey)
           if v is None:
              logger.debug("GET KEY %s return a 404" % ukey, part='kv')
              abort(404, '')
           logger.debug("GET: get time %s" % (time.time() -t0), part='kv')
           return v


        @route('/kv/:ukey#.+#', method='PUT')
        def interface_PUT_key(ukey):
           value = request.body.getvalue()
           logger.debug("KV: PUT KEY %s (len:%d)" % (ukey, len(value)), part='kv')
           force = request.GET.get('force', 'False') == 'True'
           meta = request.GET.get('meta', None)
           if meta:
               meta = json.loads(meta)
           ttl = int(request.GET.get('ttl', '0'))
           self.put_key(ukey, value, force=force, meta=meta, ttl=ttl)
           return


        @route('/kv/:ukey#.+#', method='DELETE')
        def interface_DELETE_key(ukey):
           logger.debug("KV: DELETE KEY %s" % ukey, part='kv')
           self.delete_key(ukey)


        @route('/kv/')
        def list_keys():
            response.content_type = 'application/json'
            l = list(self.kv.db.RangeIter(include_value = False))
            return json.dumps(l)
        

        @route('/kv-meta/changed/:t', method='GET')
        def changed_since(t):
            response.content_type = 'application/json'
            t = int(t)
            return json.dumps(self.kv.changed_since(t))


        @route('/agent/propagate/libexec', method='GET')
        def propage_libexec():            
            logger.debug("Call to propagate-configuraion", part='http')
            if not os.path.exists(self.libexec_dir):
                abort(400, 'Libexec directory is not existing')
            all_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(os.path.abspath(self.libexec_dir))  for f in filenames]
            for fname in all_files:
                path = fname[len(os.path.abspath(self.libexec_dir))+1:]
                # first try to open the path and get a hash of the local file
                f = open(fname, 'rb')
                _hash = hashlib.sha1(f.read()).hexdigest()
                f.close()
                logger.debug("propagate saving FILE %s into the KV space" % fname, part='http')
                f = tempfile.TemporaryFile()
                
                with tarfile.open(fileobj=f, mode="w:gz") as tar:
                    tar.add(fname, arcname=path)
                f.seek(0)
                zbuf = f.read()
                f.close()
                buf64 = base64.b64encode(zbuf)

                logger.debug("propagate READ A %d file %s and compressed into a %d one..." % (len(zbuf), path, len(buf64)), part='http')
                key = '__libexec/%s' % path
                
                self.put_key(key, buf64)
                
                payload = {'type':'libexec', 'path':path, 'hash':_hash}
                self.stack_event_broadcast(payload)


        @route('/agent/propagate/configuration', method='GET')
        def propage_configuration():            
            logger.debug("propagate conf call TO PROPAGATE CONFIGURATION", part='http')
            if not os.path.exists(self.configuration_dir):
                abort(400, 'Configuration directory is not existing')
            all_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(os.path.abspath(self.configuration_dir))  for f in filenames]
            # we keep a list of (path, sha1) combo for the
            ok_files = []
            for fname in all_files:
                path = fname[len(os.path.abspath(self.configuration_dir))+1:]
                # Do not send our local.json, it's local, not global!
                if path == 'local.json':
                   continue
                # first try to open the path and get a hash of the local file
                f = open(fname, 'rb')
                _hash = hashlib.sha1(f.read()).hexdigest()
                f.close()
                
                # save this entry
                ok_files.append( (path, _hash) )
                
                logger.debug("propagate conf SAVING FILE %s into the KV space" % fname, part='http')
                # get a tar for this file, and base64 it
                f = tempfile.TemporaryFile()                
                with tarfile.open(fileobj=f, mode="w:gz") as tar:
                    tar.add(fname, arcname=path)
                f.seek(0)
                zbuf = f.read()
                f.close()
                buf64 = base64.b64encode(zbuf)

                print "READ A %d file %s and compressed into a %d one..." % (len(zbuf), path, len(buf64))
                key = '__configuration/%s' % path
                print "READ PUT KEY", key
                self.put_key(key, buf64)
                
                payload = {'type':'configuration', 'path':path, 'hash':_hash}
                self.stack_event_broadcast(payload)

            ok_files = [fname[len(os.path.abspath(self.configuration_dir))+1:] for fname in all_files]
            logger.debug("propagate configuration All files", ok_files, part='http')
            j = json.dumps(ok_files)
            zj = zlib.compress(j, 9)
            zj64 = base64.b64encode(zj)
            self.put_key('__configuration', zj64)
            payload = {'type':'configuration-cleanup'}
            self.stack_event_broadcast(payload)



        @route('/configuration/update', method='PUT')
        def protected():
           value = request.body.getvalue()
           logger.debug("HTTP: configuration update put %s" % (value), part='http')
           try:
               update = json.loads(value)
           except ValueError: # bad json...
               return abort(400, 'Bad json data')
           local_file = os.path.join(self.configuration_dir, 'local.json')
           j = {}
           with open(local_file, 'r') as f:
               buf = f.read()
               j = json.loads(buf)
           j.update(update)
           # Now save it
           with open(local_file, 'w') as f:
               f.write(json.dumps(j, sort_keys=True, indent=4))
           # Load the data we can
           self.open_cfg_file(local_file)
           logger.debug('HTTP configuration update, now got %s' % j, part='http')
           return


        @route('/configuration', method='GET')
        def get_configuration():
            response.content_type = 'application/json'
            logger.debug("HTTP: configuration get ", part='http')
            local_file = os.path.join(self.configuration_dir, 'local.json')
            j = {}
            with open(local_file, 'r') as f:
                buf = f.read()
                j = json.loads(buf)
            return j


        @route('/agent/join/:other')
        def agent_join(other):
            response.content_type = 'application/json'
            addr = other
            port = self.port
            if ':' in other:
                parts = other.split(':', 1)
                addr = parts[0]
                port = int(parts[1])
            tgt = (addr, port)
            logger.debug("HTTP: agent join for %s:%s " % (addr, port), part='http')
            r = self.do_push_pull(tgt)
            logger.debug("HTTP: agent join for %s:%s result:%s" % (addr, port, r), part='http')
            return json.dumps(r)


        @route('/list/')
        @route('/list/:key')
        def get_ts_keys(key=''):
            response.content_type = 'application/json'
            if self.ts is None:
                return json.dumps([])
            return json.dumps(self.ts.list_keys(key))





        @route('/exec/:tag')
        def launch_exec(tag='*'):
            response.content_type = 'application/json'
            if self.mfkey_priv is None:
                return abort(400, 'No master private key')
            cmd = request.GET.get('cmd', 'uname -a')
            uid = self.launch_exec(cmd, tag)
            return uid


        @route('/exec-get/:cid')
        def launch_exec(cid):
            response.content_type = 'application/json'
            res = self.execs.get(cid, None)
            if res is None:
                return abort(400, 'BAD cid')
            return json.dumps(res)
        
            
        # Enable cors on all our calls
        bapp = bottle.app()
        bapp.install(EnableCors())

        # Will lock for
        run(host=self.addr, port=self.port, server='cherrypy', numthreads=64)# 256?

        
    # Launch an exec thread and save its uuid so we can keep a look at it then
    def launch_exec(self, cmd, tag):
        uid = uuid.uuid1().get_hex()
        e = {'cmd':cmd, 'tag':tag, 'thread':None, 'res':{}, 'nodes':[], 'ctime':int(time.time())}
        self.execs[uid] = e
        t = threader.create_and_launch(self.do_exec_thread, name='exec-%s' % uid, args=(uid,))
        return uid

    
    # Look at all nodes, ask them a challenge to manage with our priv key (they all got
    # our pub key)
    def do_exec_thread(self, uid):
        # first look at which command we need to run
        e = self.execs[uid]
        tag = e['tag']
        cmd = e['cmd']
        logger.debug('EXEC ask for launching command', cmd, part='exec')
        all_uuids = []
        with self.nodes_lock: # get the nodes that follow the tag (or all in *)
            for (uuid, n) in self.nodes.iteritems():
                if tag == '*' or tag in n['tags']:
                    all_uuids.append(uuid)
        e['nodes'] = all_uuids
        asks = {}
        e['res'] = asks
        for nuid in all_uuids:
            node = self.nodes.get(nuid, None)
            if node is None: # was removed, don't play lotery today...
                continue
            # Get a socekt to talk with this node
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            
            d = {'node':node, 'challenge':'', 'state':'pending', 'rc':3, 'output':'', 'err':''}
            asks[nuid] = d
            logger.debug('EXEC asking for node %s' % node['name'], part='exec')
            payload = {'type':'/exec/challenge/ask', 'fr': self.uuid}
            packet = json.dumps(payload)
            enc_packet = self.encrypt(packet)
            logger.debug('EXEC: sending a challenge request to %s' % node['name'], part='exec')
            sock.sendto(enc_packet, (node['addr'], node['port']))
            # Now wait for a return
            sock.settimeout(3)
            try:
                raw = sock.recv(1024)
            except socket.timeout, exp:
                logger.error('EXEC challenge ask timeout from node %s : %s' % (node['name'], exp), part='exec')
                sock.close()
                d['state'] = 'error'
                continue
            msg = self.decrypt(raw)
            if msg is None:
                logger.error('EXEC bad return from node %s' % node['name'], part='exec')
                sock.close()
                d['state'] = 'error'
                continue
            try:
                ret = json.loads(msg)
            except ValueError, exp:
                logger.error('EXEC bad return from node %s : %s' % (node['name'], exp), part='exec')
                sock.close()
                d['state'] = 'error'
                continue
            cid = ret.get('cid', '') # challenge id
            challenge64 = ret.get('challenge', '')
            if not challenge64 or not cid:
                logger.error('EXEC bad return from node %s : no challenge or challenge id' % node['name'], part='exec')                
                sock.close()
                d['state'] = 'error'
                continue
            try:
                challenge = base64.b64decode(challenge64)
            except ValueError:
                logger.error('EXEC bad return from node %s : invalid base64' % node['name'], part='exec')
                sock.close()
                d['state'] = 'error'
                continue
            # Now send back the challenge response # dumy: add real RSA cypher here of course :)
            logger.debug('EXEC got a return from challenge ask from %s: %s' %  (node['name'], cid), part='gossip')
            try:
                response = self.mfkey_priv.decrypt(challenge)
            except Exception, exp:
                logger.error('EXEC bad challenge encoding from %s:%s' % (node['name'], exp))
                sock.close()
                d['state'] = 'error'
                continue
            response64 = base64.b64encode(response)
            payload = {'type':'/exec/challenge/return', 'fr': self.uuid,
                       'cid':cid, 'response':response64, 
                       'cmd':cmd}
            packet = json.dumps(payload)
            enc_packet = self.encrypt(packet)
            logger.debug('EXEC: sending a challenge response to %s' % node['name'], part='exec')
            sock.sendto(enc_packet, (node['addr'], node['port']))
            
            # Now wait a return from this node exec
            sock.settimeout(3)
            try:
                raw = sock.recv(1024)
            except socket.timeout, exp:
                logger.error('EXEC done return timeout from node %s : %s' % (node['name'], exp), part='exec')
                sock.close()
                d['state'] = 'error'
                continue
            msg = self.decrypt(raw)
            if msg is None:
                logger.error('EXEC bad return from node %s' % node['name'], part='exec')
                sock.close()
                d['state'] = 'error'
                continue
            try:
                ret = json.loads(msg)
            except ValueError, exp:
                logger.error('EXEC bad return from node %s : %s' % (node['name'], exp), part='exec')
                sock.close()
                d['state'] = 'error'
                continue
            cid = ret.get('cid', '') # challenge id
            if not cid: # bad return?
                logger.error('EXEC bad return from node %s : no cid' % node['name'], part='exec')
                d['state'] = 'error'
                continue
            v = self.get_key('__exec/%s' % cid)
            if v is None:
                logger.error('EXEC void KV entry from return from %s and cid %s' % (node['name'], cid), part='exec')
                d['state'] = 'error'
                continue
            print "EXEC FUCK", v, type(v)
            try:
                e = json.loads(v)
            except ValueError, exp:
                logger.error('EXEC bad json entry return from %s and cid %s: %s' % (node['name'], cid, exp), part='exec')
                d['state'] = 'error'
                continue
            logger.debug('EXEC GOT A RETURN! %s %s %s %s' % (node['name'], cid, e['rc'], e['output']), part='exec')
            d['state'] = 'done'
            d['output'] = e['output']
            d['err'] = e['err']
            d['rc'] = e['rc']
            
            

    # Get a key from whateverr me or another node
    def get_key(self, ukey):
       # we have to compute our internal key mapping. For user key it's: /data/KEY
       key = ukey
       hkey = hashlib.sha1(key).hexdigest()
       nuuid = self.find_kv_node(hkey)
       logger.debug('KV: key %s is managed by %s' % (ukey, nuuid), part='kv')
       # that's me :)
       if nuuid == self.uuid:
          logger.debug('KV: (get) My job to find %s' % key, part='kv')
          v = self.kv.get(key)
          return v
       else:
          n = self.nodes.get(nuuid, None)
          # Maybe the node disapears, if so bailout and say we got no luck
          if n is None:
              return None
          uri = 'http://%s:%s/kv/%s' % (n['addr'], n['port'], ukey)
          try:
             logger.debug('KV: (get) relaying to %s: %s' % (n['name'], uri), part='kv')
             r = rq.get(uri)
             if r.status_code == 404:
                logger.debug("GET KEY %s return a 404" % ukey, part='kv')
                return None
             logger.debug('KV: get founded (%d)' % len(r.text), part='kv')
             return r.text
          except rq.exceptions.RequestException, exp:
             logger.debug('KV: error asking to %s: %s' % (n['name'], str(exp)), part='kv')
             return None
    
    
    def put_key(self, ukey, value, force=False, meta=None, allow_udp=False, ttl=0, fw=False):
       # we have to compute our internal key mapping. For user key it's: /data/KEY
       key = ukey

       hkey = hashlib.sha1(key).hexdigest()

       nuuid = self.find_kv_node(hkey)
       
       _node = self.nodes.get(nuuid, None)
       _name = ''
       # The node can disapear with another thread
       if _node is not None:
           _name = _node['name']
       logger.debug('KV: key should be managed by %s(%s) for %s' % (_name, nuuid, ukey), 'kv')
       # that's me if it's really for me, or it's a force one, or it's already a forward one
       if nuuid == self.uuid or force or fw:
          logger.debug('KV: (put) I shoukd managed the key %s (force:%s) (fw:%s)' % (key, force, fw))
          self.kv.put(key, value, ttl=ttl)
          
          # We also replicate the meta data from the master node
          if meta:
              self.kv.put_meta(key, meta)

          # If we are in a force mode, so we do not launch a repl, we are not
          # the master node
          if force:
             return None
          
          # remember to save the replication back log entry too
          meta = self.kv.get_meta(ukey)
          bl = {'value':(ukey, value), 'repl':[], 'hkey':hkey, 'meta':meta}
          logger.debug('REPLICATION adding backlog entry %s' % bl, part='kv')
          self.replication_backlog[ukey] = bl
          return None
       else:
          n = self.nodes.get(nuuid, None)
          if n is None: # oups, someone is playing iwth my nodes and delete it...
              return None
          # Maybe the user did allow weak consistency, so we can use udp (like metrics)
          if allow_udp:
              try:
                  payload = {'type':'/kv/put', 'k':ukey, 'v':value, 'ttl':ttl, 'fw':True}
                  packet = json.dumps(payload)
                  enc_packet = self.encrypt(packet)
                  logger.debug('KV: PUT(udp) asking %s: %s:%s' % (n['name'], n['addr'], n['port']), part='kv')
                  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                  sock.sendto(enc_packet, (n['addr'], n['port']))
                  sock.close()
                  return None
              except Exception, exp:
                  logger.debug('KV: PUT (udp) error asking to %s: %s' % (n['name'], str(exp)), part='kv')
                  return None
          # ok no allow udp here, so we switch to a classic HTTP mode :)
          uri = 'http://%s:%s/kv/%s?ttl=%s' % (n['addr'], n['port'], ukey, ttl)
          try:
             logger.debug('KV: PUT asking %s: %s' % (n['name'], uri), part='kv')
             params = {'ttl': str(ttl)}
             r = rq.put(uri, data=value, params=params)
             logger.debug('KV: PUT return %s' % r.status_code, part='kv')
             return None
          except rq.exceptions.RequestException, exp:
             logger.debug('KV: PUT error asking to %s: %s' % (n['name'], str(exp)), part='kv')
             return None


    def delete_key(self, ukey):
       # we have to compute our internal key mapping. For user key it's: /data/KEY
       key = ukey
       
       hkey = hashlib.sha1(key).hexdigest()
       nuuid = self.find_kv_node(hkey)
       logger.debug('KV: DELETE node that manage the key %s' % nuuid, part='kv')
       # that's me :)
       if nuuid == self.uuid:
          logger.debug('KV: DELETE My job to manage %s' % key, part='kv')
          self.kv.delete(key)
          return None
       else:
          n = self.nodes.get(nuuid, None)
          # Maybe someone delete my node, it's not fair :)
          if n is None:
              return None
          uri = 'http://%s:%s/kv/%s' % (n['addr'], n['port'], ukey)
          try:
             logger.debug('KV: DELETE relaying to %s: %s' % (n['name'], uri), part='kv')
             r = rq.delete(uri, data=value)
             logger.debug('KV: DELETE return %s' % r.status_code, part='kv')
             return None
          except rq.exceptions.RequestException, exp:
             logger.debug('KV: DELETE error asking to %s: %s' % (n['name'], str(exp)), part='kv')
             return None


    def stack_put_key(self, k, v, ttl=0):
       self.put_key_buffer.append( (k,v, ttl) )


    # put from udp should be clean quick from the thread so it can listen to udp again and
    # not lost any udp message
    def put_key_reaper(self):
       while not self.interrupted:
          put_key_buffer = self.put_key_buffer
          self.put_key_buffer = []
          _t = time.time()
          if len(put_key_buffer) != 0:
              logger.info("PUT KEY BUFFER LEN", len(put_key_buffer))
          for (k,v, ttl) in put_key_buffer:
             self.put_key(k, v, ttl=ttl, allow_udp=True)
          if len(put_key_buffer) != 0:
              logger.info("PUT KEY BUFFER IN", time.time() - _t)
          
          # only sleep if we didn't work at all (busy moment)
          if len(put_key_buffer) == 0:
              time.sleep(0.1)



    def start_ts_listener(self):
       # launch metric based listeners and backend
       self.ts = TSListener(self)



    # I try to get the nodes before myself in the nodes list
    def get_my_replicats(self):
       kv_nodes = self.find_kv_nodes()
       kv_nodes.sort()

       # Maybe soneone ask us a put but we are not totally joined
       # if so do not replicate this
       if not self.uuid in kv_nodes:
           logger.log('WARNING: too early put, myself %s is not a kv nodes currently' % self.uuid, part='kv')
           return []
       
       # You can't have more replicats that you got of kv nodes
       nb_rep = min(REPLICATS, len(kv_nodes))

       idx = kv_nodes.index(self.uuid)       
       replicats = []
       for i in range(idx-nb_rep, idx):
          nuuid = kv_nodes[i]
          # we can't be a replicat of ourselve
          if nuuid == self.uuid:
              continue
          replicats.append(nuuid)
       rnames = []
       for uuid in replicats:
           # Maybe someone delete the nodes just here, so we must care about it
           n = self.nodes.get(uuid, None)
           if n:
               rnames.append(n['name'])
       
       logger.debug('REPLICATS: myself %s replicats are %s' % (self.name, rnames), part='kv')
       return replicats

    
    def do_replication_backlog_thread(self):
       logger.log('REPLICATION thread launched', part='kv')
       while not self.interrupted:
          e = None
          # Standard switch
          replication_backlog = self.replication_backlog
          self.replication_backlog = {}
          
          replicats = self.get_my_replicats()
          if len(replicats) == 0:
              time.sleep(1)
          for (ukey, bl) in replication_backlog.iteritems():
              # REF: bl = {'value':(ukey, value), 'repl':[], 'hkey':hkey, 'meta':meta}
              hkey = bl['hkey']
              _, value = bl['value']
              for uuid in replicats:
                  _node = self.nodes.get(uuid, None)
                  # Someone just delete my node, not fair :)
                  if _node is None:
                      continue
                  logger.debug('REPLICATION thread manage entry to %s(%s) : %s' % (_node['name'], uuid, bl), part='kv')
                  
                  # Now send it :)
                  n = _node
                  uri = 'http://%s:%s/kv/%s?force=True' % (n['addr'], n['port'], ukey)
                  try:
                      logger.debug('KV: PUT(force) asking %s: %s' % (n['name'], uri), part='kv')
                      params = {'force': True, 'meta':json.dumps(bl['meta'])}
                      r = rq.put(uri, data=value, params=params)
                      logger.debug('KV: PUT(force) return %s' % r, part='kv')
                  except rq.exceptions.RequestException, exp:
                      logger.debug('KV: PUT(force) error asking to %s: %s' % (n['name'], str(exp)), part='kv')
          time.sleep(1)


    # The first sync thread will ask to our replicats for their lately changed value
    # and we will get the key/value from it
    def do_replication_first_sync_thread(self):
       if not 'kv' in self.tags:
           logger.log('SYNC no need, I am not a KV node', part='kv')
           return
       logger.log('SYNC thread launched', part='kv')
       # We will look until we found a repl that answer us :)
       while True:
           repls = self.get_my_replicats()
           for repluuid in repls:
               repl = self.nodes.get(repluuid, None)
               # Maybe someone just delete my node, if so skip it
               if repl is None:
                   continue
               addr = repl['addr']
               port = repl['port']
               logger.log('SYNC try to sync from %s since the time %s' % (repl['name'], self.last_alive), part='kv')
               uri = 'http://%s:%s/kv-meta/changed/%d' % (addr, port, self.last_alive)
               try:
                   r = rq.get(uri)
                   logger.debug("SYNC kv-changed response from %s "%repl['name'], r, part='kv')
                   try:
                       to_merge = json.loads(r.text)
                   except ValueError, exp:
                       logger.debug('SYNC : error asking to %s: %s' % (repl['name'], str(exp)), part='kv')
                       continue
                   self.kv.do_merge(to_merge)
                   logger.debug("SYNC thread done, bailing out", part='kv')
                   return
               except rq.exceptions.RequestException, exp:
                   logger.debug('SYNC : error asking to %s: %s' % (repl['name'], str(exp)), part='kv')
                   continue
           time.sleep(1)
                   

    # Main thread for launching checks (each with its own thread)
    def do_check_thread(self):
       logger.log('CHECK thread launched', part='check')
       cur_launchs = {}
       while not self.interrupted:
          now = int(time.time())
          for (cid, check) in self.checks.iteritems():
             # maybe this chck is not a activated one for us, if so, bail out
             if not cid in self.active_checks:
                continue
             # maybe a check is already running
             if cid in cur_launchs:
                continue
             # else look at the time
             last_check = check['last_check']
             interval   = int(check['interval'].split('s')[0]) # todo manage like it should
                                                               #in the conf reading phase
             interval = random.randint(int(0.9*interval), int(1.1*interval))
             #interval = random.randint(1, 2*interval)
             if last_check < now - interval:
                # randomize a bit the checks
                script = check['script']
                logger.debug('CHECK: launching check %s:%s' % (cid, script), part='check')
                t = threader.create_and_launch(self.launch_check, name='check-%s' % cid, args=(check,))
                cur_launchs[cid] = t

          to_del = []
          for (cid, t) in cur_launchs.iteritems():
             if not t.is_alive():
                t.join()
                to_del.append(cid)
          for cid in to_del:
             del cur_launchs[cid]

          time.sleep(1)


    # Main thread for launching collectors
    def do_collector_thread(self):
       logger.log('COLLECTOR thread launched', part='check')
       cur_launchs = {}
       while not self.interrupted:
           #logger.debug('... collectors...')
           now = int(time.time())
           for (cls, e) in self.collectors.iteritems():
               colname = e['name']
               inst = e['inst']
               # maybe a collection is already running
               if colname in cur_launchs:
                   continue
               if now >= e['next_check']:
                   logger.debug('COLLECTOR: launching collector %s' % colname, part='check')
                   t = threader.create_and_launch(inst.main, name='collector-%s' % colname)#, args=(,))
                   cur_launchs[colname] = t
                   e['next_check'] += 10

           to_del = []
           for (colname, t) in cur_launchs.iteritems():
               if not t.is_alive():
                   t.join()
                   to_del.append(colname)
           for colname in to_del:
               del cur_launchs[colname]

           time.sleep(1)


    # Try to find the params for a macro in the foloowing objets, in that order:
    # * check
    # * service
    # * main configuration
    def _found_params(self, m, check):
          parts = [m]
          # if we got a |, we got a default value somewhere
          if '|' in m:
             parts = m.split('|', 1)
          change_to = ''
          for p in parts:
             elts = [p]
             if '.' in p:
                elts = p.split('.')
             elts = [e.strip() for e in elts]

             # we will try to grok into our cfg_data for the k1.k2.k3 =>
             # self.cfg_data[k1][k2][k3] entry if exists
             d = None
             founded = False

             # We will look into the check>service>global order
             # but skip serviec if it's not related with the check
             sname = check.get('service', '')
             service = {}
             find_into = [check, self.cfg_data]
             if sname and sname in self.services:
                service = self.services.get(sname)
                find_into = [check, service, self.cfg_data]

             for tgt in find_into:
                (lfounded, ld) = self._found_params_inside(elts, tgt)
                if not lfounded:
                   continue
                if lfounded:
                   founded = True
                   d = ld
                   break
             if not founded:
                continue
             change_to = str(d)
             break
          return change_to


    # Try to found a elts= k1.k2.k3 => d[k1][k2][k3] entry
    # if exists
    def _found_params_inside(self, elts, d):
             founded = False
             for e in elts:
                if not e in d:
                   founded = False
                   break
                d = d[e]
                founded = True
             return (founded, d)
       

    # Launch a check sub-process as a thread
    def launch_check(self, check):
       script = check['script']
       logger.debug("CHECK start: MACRO launching %s" % script, part='check')
       # First we need to change the script with good macros (between $$)       
       it = self.macro_pat.finditer(script)
       macros = [m.groups() for m in it]
       # can be ('$ load.warning | 95$', 'load.warning | 95') for example
       for (to_repl, m) in macros:
          change_to = self._found_params(m, check)
          script = script.replace(to_repl, change_to)
       logger.debug("MACRO finally computed", script, part='check')

       p = subprocess.Popen(script, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, preexec_fn=os.setsid)
       output, err = p.communicate()
       rc = p.returncode
       logger.debug("CHECK RETURN %s : %s %s %s" % (check['id'], rc, output, err), part='check')
       check['state'] = {0:'OK', 1:'WARNING', 2:'CRITICAL', 3:'UNKNOWN'}.get(rc, 'UNKNOWN')
       if 0 <= rc <= 3:
           check['state_id'] = rc
       else:
           check['state_id'] = 3
       
       check['output'] = output + err
       check['last_check'] = int(time.time())
       self.analyse_check(check)
    
    
    # get a check return and look it it did change a service state. Also save
    # the result in the __health KV
    def analyse_check(self, check):
       logger.debug('CHECK we got a check return, deal with it for %s' % check, part='check')
       
       # If the check is related to a service, import the result into the service
       # and look for a service state change
       sname = check.get('service', '')
       if sname and sname in self.services:
           service = self.services.get(sname)
           logger.debug('CHECK is related to a service, deal with it! %s => %s' % (check, service), part='check')
           sstate_id = service.get('state_id')
           cstate_id = check.get('state_id')
           if cstate_id != sstate_id:
               service['state_id'] = cstate_id
               logger.log('CHECK: we got a service state change from %s to %s for %s' % (sstate_id, cstate_id, service['name']), part='check')
               # This node cannot be deleted, so we don't need a protection here
               node = self.nodes.get(self.uuid)                   
               self.incarnation += 1
               node['incarnation'] = self.incarnation
               self.stack_alive_broadcast(node)
           else:
               logger.debug('CHECK: service %s did not change (%s)' % (service['name'], sstate_id), part='check')
       
       # We finally put the result in the KV database
       self.put_check(check)
    
    
    # Save the check as a jsono object into the __health/ KV part
    def put_check(self, check):
       value = json.dumps(check)
       key = '__health/%s/%s' % (self.name, check['name'])
       logger.debug('CHECK SAVING %s:%s(len=%d)' % (key, value, len(value)), part='check')
       self.put_key(key, value, allow_udp=True)
       
       # Now groking metrics from check
       elts = check['output'].split('|', 1)
       output = elts[0]
       try:
           perfdata = elts[1]
       except IndexError:
           perfdata = ''
       
       # if not perfdata, bail out
       if not perfdata:
           return
       
       datas = []
       cname = check['name'].replace('/','.')
       now = int(time.time())
       perfdatas = PerfDatas(perfdata)
       for m in perfdatas:
           if m.name is None or m.value is None:
               continue # skip this invalid perfdata
           
           logger.debug('GOT PERFDATAS', m, part='check')
           logger.debug('GOT PERFDATAS', m.name, part='check')
           logger.debug('GOT PERFDATAS', m.value, part='check')
           e = {'mname':'.'.join([self.name, cname, m.name]), 'timestamp':now, 'value':m.value}
           logger.debug('PUT PERFDATA', e, part='check')
           datas.append(e)

       self.put_graphite_datas(datas)
       

    # TODO: RE-factorize with the TS code part
    def put_graphite_datas(self, datas):
      forwards = {}
      for e in datas:
         mname, value, timestamp = e['mname'], e['value'], e['timestamp']
         hkey = hashlib.sha1(mname).hexdigest()
         ts_node_manager = self.find_ts_node(hkey)
         # if it's me that manage this key, I add it in my backend
         if ts_node_manager == self.uuid:
             logger.debug("I am the TS node manager")
             print "HOW ADDING", timestamp, mname, value, type(timestamp), type(mname), type(value)
             self.ts.tsb.add_value(timestamp, mname, value)
         # not me? stack a forwarder
         else:
             logger.debug("The node manager for this Ts is ", ts_node_manager)
             l = forwards.get(ts_node_manager, [])
             ##Transform into a graphite line
             line = '%s %s %s' % (mname, value, timestamp)
             l.append(line)
             forwards[ts_node_manager] = l

      for (uuid, lst) in forwards.iteritems():
          node = self.nodes.get(uuid, None)
          # maybe the node disapear? bail out, we are not lucky
          if node is None:
              continue
          packets = []
          # first compute the packets
          buf = ''
          for line in lst:
              buf += line+'\n'
              if len(buf) > 1024:
                  packets.append(buf)
                  buf = ''
          if buf != '':
              packets.append(buf)

          # UDP
          sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          for packet in packets:
             # do NOT use the node['port'], it's the internal communication, not the graphite one!
             sock.sendto(packet, (node['addr'], 2003))
          sock.close()


    # Will delete all checks into the kv and update new values, but in a thread
    def update_checks_kv(self):
       def do_update_checks_kv(self):
          logger.debug("CHECK UPDATING KV checks", part='kv')
          names = []
          for (cid, check) in self.checks.iteritems():
              # Only the checks that we are really managing
              if cid in self.active_checks:
                  names.append(check['name'])
                  self.put_check(check)
          all_checks = json.dumps(names)
          key = '__health/%s' % self.name
          self.put_key(key, all_checks)

       # Ok go launch it :)
       threader.create_and_launch(do_update_checks_kv, args=(self,))


    # Someone ask us to launch a new command (was already auth by RSA keys)
    def do_launch_exec(self, cid, cmd, addr):
        logger.debug('EXEC launching a command %s' % cmd, part='exec')
        
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, preexec_fn=os.setsid)
        output, err = p.communicate() # Will lock here
        rc = p.returncode
        logger.debug("EXEC RETURN for command %s : %s %s %s" % (cmd, rc, output, err), part='exec')
        o = {'output':output, 'rc':rc, 'err':err}
        j = json.dumps(o)
        # Save the return and put it in the KV space
        key = '__exec/%s' % cid
        self.put_key(key, j, ttl=3600) # only one hour live is good :)

        # Now send a finish to the asker
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            
        payload = {'type':'/exec/done', 'cid': cid}
        packet = json.dumps(payload)
        enc_packet = self.encrypt(packet)
        logger.debug('EXEC: sending a exec done packet %s:%s' % addr, part='exec')
        try:
            sock.sendto(enc_packet, addr)
            sock.close()
        except Exception, exp:
            sock.close() #
        
        


    # Thread that will look for libexec/configuration change events,
    # will get the newest value in the KV and dump the files
    def launch_update_libexec_cfg_thread(self):
       def do_update_libexec_cfg_thread(self):
          while not self.interrupted:
             # work on a clean list
             libexec_to_update = self.libexec_to_update
             self.libexec_to_update = []
             for (p, _hash) in libexec_to_update:
                 logger.debug("LIBEXEC WE NEED TO UPDATE THE LIBEXEC PATH", p, "with the hash", _hash, part='propagate')
                 fname = os.path.normpath(os.path.join(self.libexec_dir, p))

                # check if we are still in the libexec dir and not higer, somewhere
                 # like in a ~/.ssh or an /etc...
                 if not fname.startswith(self.libexec_dir):
                     logger.log('WARNING (SECURITY): trying to update the path %s that is not in libexec dir, bailing out' % fname, part='propagate')
                     continue
                 # If it exists, try to look at the _hash so maybe we don't have to load it again
                 if os.path.exists(fname):
                     try:
                         f = open(fname, 'rb')
                         _lhash = hashlib.sha1(f.read()).hexdigest()
                         f.close()
                     except Exception, exp:
                         logger.log('do_update_libexec_cfg_thread:: error in opening the %s file: %s' % (fname, exp), part='propagate')
                         _lhash = ''
                     if _lhash == _hash:
                         logger.debug('LIBEXEC update, not need for the local file %s, hash are the same' % fname, part='propagate')
                         continue
                 # ok here we need to load the KV value (a base64 tarfile)
                 v64 = self.get_key('__libexec/%s' % p)
                 if v64 is None:
                     logger.log('WARNING: cannot load the libexec script from kv %s' % p, part='propagate')
                     continue
                 vtar = base64.b64decode(v64)
                 f = cStringIO.StringIO(vtar)
                 with tarfile.open(fileobj=f, mode="r:gz") as tar:
                     files = tar.getmembers()
                     if len(files) != 1:
                         logger.log('WARNING: too much files in a libexec KV entry %d' % len(files), part='propagate')
                         continue
                     _f = files[0]
                     _fname = os.path.normpath(_f.name)
                     if not _f.isfile() or os.path.isabs(_fname):
                         logger.log('WARNING: (security) invalid libexec KV entry (not a file or absolute path) for %s' % _fname, part='propagate')
                         continue
                     
                     # ok the file is good, we can extract it
                     tempdir = tempfile.mkdtemp()
                     tar.extract(_f, path=tempdir)
                     
                     # now we can move all the tempdir content into the libexec dir
                     to_move = os.listdir(tempdir)
                     for e in to_move:
                         copy_dir(os.path.join(tempdir, e), self.libexec_dir)
                         logger.debug('LIBEXEC: we just upadte the %s file with a new version' % _fname, part='propagate')
                     # we can clean the tempdir as we don't use it anymore
                     shutil.rmtree(tempdir)
                 f.close()

             # Now the configuration part
             configuration_to_update = self.configuration_to_update
             self.configuration_to_update = []
             for (p, _hash) in configuration_to_update:
                 logger.debug("CONFIGURATION WE NEED TO UPDATE THE CONFIGURATION PATH", p, "with the hash", _hash, part='propagate')
                 fname = os.path.normpath(os.path.join(self.configuration_dir, p))
                 
                # check if we are still in the configuration dir and not higer, somewhere
                 # like in a ~/.ssh or an /etc...
                 if not fname.startswith(self.configuration_dir):
                     logger.log('WARNING (SECURITY): trying to update the path %s that is not in configuration dir, bailing out' % fname, part='propagate')
                     continue
                 # If it exists, try to look at the _hash so maybe we don't have to load it again
                 if os.path.exists(fname):
                     try:
                         f = open(fname, 'rb')
                         _lhash = hashlib.sha1(f.read()).hexdigest()
                         f.close()
                     except Exception, exp:
                         logger.log('do_update_configuration_cfg_thread:: error in opening the %s file: %s' % (fname, exp), part='propagate')
                         _lhash = ''
                     if _lhash == _hash:
                         logger.debug('CONFIGURATION update, not need for the local file %s, hash are the same' % fname, part='propagate')
                         continue
                 # ok here we need to load the KV value (a base64 tarfile)
                 v64 = self.get_key('__configuration/%s' % p)
                 if v64 is None:
                     logger.log('WARNING: cannot load the configuration script from kv %s' % p, part='propagate')
                     continue
                 vtar = base64.b64decode(v64)
                 f = cStringIO.StringIO(vtar)
                 with tarfile.open(fileobj=f, mode="r:gz") as tar:
                     files = tar.getmembers()
                     if len(files) != 1:
                         logger.log('WARNING: too much files in a configuration KV entry %d' % len(files), part='propagate')
                         continue
                     _f = files[0]
                     _fname = os.path.normpath(_f.name)
                     if not _f.isfile() or os.path.isabs(_fname):
                         logger.log('WARNING: (security) invalid configuration KV entry (not a file or absolute path) for %s' % _fname, part='propagate')
                         continue
                     # ok the file is good, we can extract it
                     tempdir = tempfile.mkdtemp()
                     tar.extract(_f, path=tempdir)

                     # now we can move all the tempdir content into the configuration dir
                     to_move = os.listdir(tempdir)
                     for e in to_move:
                         copy_dir(os.path.join(tempdir, e), self.configuration_dir)
                         logger.debug('CONFIGURATION: we just upadte the %s file with a new version' % _fname, part='propagate')
                     # we can clean the tempdir as we don't use it anymore
                     shutil.rmtree(tempdir)
                 f.close()



             # We finish to load all, we take a bit sleep now...
             time.sleep(1)

       # Go launch it
       threader.create_and_launch(do_update_libexec_cfg_thread, args=(self,))


    # find all nearly alive nodes with a specific tag
    def find_tag_nodes(self, tag):
        nodes = []
        with self.nodes_lock:
            for (uuid, node) in self.nodes.iteritems():
                if node['state'] in ['dead', 'leave']:
                    continue
                tags = node['tags']
                if tag in tags:
                    nodes.append(uuid)
        return nodes


    # find the good ring node for a tag and for a key
    def find_tag_node(self, tag, hkey):
       kv_nodes = self.find_tag_nodes(tag)

       # No kv nodes? oups, set myself so
       if len(kv_nodes) == 0:
           return self.uuid

       kv_nodes.sort()

       idx = bisect.bisect_right(kv_nodes, hkey) - 1
       #logger.debug("IDX %d" % idx, hkey, kv_nodes, len(kv_nodes))
       nuuid = kv_nodes[idx]
       return nuuid

       
    def find_kv_nodes(self):
       return self.find_tag_nodes('kv')

    def find_kv_node(self, hkey):
       return self.find_tag_node('kv', hkey)

    def find_ts_nodes(self, hkey):
       return self.find_tag_nodes('ts')
       
    def find_ts_node(self, hkey):
       return self.find_tag_node('ts', hkey)


    def retention_nodes(self, force=False):
        # Ok we got no nodes? something is strange, we don't save this :)
        if len(self.nodes) == 0:
            return
        
        now = int(time.time())
        if force or (now - 60 > self.last_retention_write):
            with open(self.nodes_file+'.tmp', 'w') as f:
                nodes = {}
                with self.nodes_lock:
                    nodes = copy.copy(self.nodes)
                f.write(json.dumps(nodes))
            # now more the tmp file into the real one
            shutil.move(self.nodes_file+'.tmp', self.nodes_file)

            # Same for the incarnation data!
            with open(self.incarnation_file+'.tmp', 'w') as f:
                f.write(json.dumps(self.incarnation))
            # now more the tmp file into the real one
            shutil.move(self.incarnation_file+'.tmp', self.incarnation_file)
            
            with open(self.check_retention+'.tmp', 'w') as f:
               f.write(json.dumps(self.checks))
            # now move the tmp into the real one
            shutil.move(self.check_retention+'.tmp', self.check_retention)

            with open(self.service_retention+'.tmp', 'w') as f:
               f.write(json.dumps(self.services))
            # now move the tmp into the real one
            shutil.move(self.service_retention+'.tmp', self.service_retention)

            with open(self.last_alive_file+'.tmp', 'w') as f:
               f.write(json.dumps(int(time.time())))
            # now move the tmp into the real one
            shutil.move(self.last_alive_file+'.tmp', self.last_alive_file)
            
            self.last_retention_write = now

                        
            
    def count(self, state):
        nodes = {}
        with self.nodes_lock:
            nodes = copy.copy(self.nodes)
        return len( [n for n in nodes.values() if n['state'] == state])

    
    # Guess what? yes, it is the main function
    def main(self):
        # be sure the check list are really updated now our litners are ok
        self.update_checks_kv()
        
        logger.log('Go go run!')
        i = -1
        while not self.interrupted:
            i += 1
            if i % 10 == 0:
                #logger.debug('KNOWN NODES: %s' % ','.join([ n['name'] for n in self.nodes.values()] ) )
                nodes = {}
                nodes = self.nodes.copy()
                logger.debug('KNOWN NODES: %d, alive:%d, suspect:%d, dead:%d, leave:%d' % (len(self.nodes), self.count('alive'), self.count('suspect'), self.count('dead'), self.count('leave')), part='gossip')
                if self.count('dead') > 0:
                    logger.debug('DEADS: %s' % ','.join([ n['name'] for n in nodes.values() if n['state'] == 'dead']), part='gossip')

            if i % 15 == 0:
                threader.create_and_launch(self.launch_full_sync)

            if i % 2 == 1:
                threader.create_and_launch(self.ping_another)

            self.launch_gossip()

            self.look_at_deads()
            
            self.retention_nodes()
            
            self.clean_old_events()

            #if self.webso:
            #    self.webso.send_all('.')

            # Look if we lost some threads or not
            threader.check_alives()

            time.sleep(1)
            
            #if i % 30 == 0:
            #    from meliae import scanner
            #    scanner.dump_all_objects( '/tmp/memory-%s' % self.name)

        self.retention_nodes(force=True)

        logger.log('Exiting')
    
        
    # get my own node entry
    def get_boostrap_node(self):
        node = {'addr':self.addr, 'port':self.port, 'name':self.name,
                'incarnation':self.incarnation, 'uuid':self.uuid, 'state':'alive', 'tags':self.tags,
                'services':{}}
        return node
    
    
    # suspect nodes are set with a suspect_time entry. If it's too old,
    # set the node as dead, and broadcast the information to everyone
    def look_at_deads(self):
        # suspect a node for 5 * log(n+1) * interval
        node_scale = math.ceil(math.log10(float(len(self.nodes) + 1)))
        probe_interval = 1
        suspicion_mult = 5
        suspect_timeout = suspicion_mult * node_scale * probe_interval
        leave_timeout = suspect_timeout * 3 # something like 30s
        
        #print "SUSPECT timeout", suspect_timeout
        now = int(time.time())
        nodes = {}
        with self.nodes_lock:
            for node in self.nodes.values():
                # Only look at suspect nodes of course...
                if node['state'] != 'suspect':
                    continue
                stime = node.get('suspect_time', now)
                if stime < (now - suspect_timeout):
                    logger.log("SUSPECT: NODE", node['name'], node['incarnation'], node['state'], "is NOW DEAD", part='gossip')
                    node['state'] = 'dead'
                    self.stack_dead_broadcast(node)

        # Now for leave nodes, this time we will really remove the entry from our nodes
        to_del = []
        for (uuid, node) in nodes.iteritems():
            # Only look at suspect nodes of course...
            if node['state'] != 'leave':
                continue
            ltime = node.get('leave_time', now)
            print "LEAVE TIME", node['name'], ltime, now - leave_timeout, (now - leave_timeout) - ltime
            if ltime < (now - leave_timeout):
                logger.log("LEAVE: NODE", node['name'], node['incarnation'], node['state'], "is now definitivly leaved. We remove it from our nodes", part='gossip')
                to_del.append(uuid)
        # now really remove them from our list :)
        for uuid in to_del:
            try:
                del self.nodes[uuid]
            except IndexError: # not here? it was was we want
                pass
        


    # Someone suspect a node, so believe it
    def set_suspect(self, suspect):
        addr = suspect['addr']
        port = suspect['port']
        name = suspect['name']
        incarnation = suspect['incarnation']
        uuid = suspect['uuid']
        tags = suspect.get('tags', [])
        services = suspect.get('services', {})
        state = 'suspect'
        
        # Maybe we didn't even have this nodes in our list?
        if not uuid in self.nodes:
            return
        
        node = self.nodes.get(uuid, None)
        # Maybe it vanish by another threads?
        if node is None:
            return

        # Maybe this data is too old
        if incarnation < node['incarnation']:
            return

        # We only case about into about alive nodes, dead and suspect
        # are not interesting :)
        if node['state'] != 'alive':
            return
        
        # Maybe it's us?? We need to say FUCKING NO, I'm alive!!
        if uuid == self.uuid:
            logger.log('SUSPECT: SOMEONE THINK I AM SUSPECT, BUT I AM ALIVE', part='gossip')
            self.incarnation += 1
            node['incarnation'] = self.incarnation
            self.stack_alive_broadcast(node)
            return

        logger.log('SUSPECTING: I suspect node %s' % node['name'], part='gossip')
        # Ok it's definitivly someone else that is now suspected, update this, and update it :)
        node['incarnation'] = incarnation
        node['state'] = state
        node['suspect_time'] = int(time.time())
        node['tags'] = tags
        node['services'] = services
        self.stack_suspect_broadcast(node)




    # Someone ask us about a leave node, so believe it
    # Leave node are about all states, so we don't filter by current state
    # if the incarnation is ok, we believe it
    def set_leave(self, leaved):
        addr = leaved['addr']
        port = leaved['port']
        name = leaved['name']
        incarnation = leaved['incarnation']
        uuid = leaved['uuid']
        tags = leaved.get('tags', [])
        services = leaved.get('services', {})
        state = 'leave'
        
        print "SET_LEAVE::", leaved
        
        # Maybe we didn't even have this nodes in our list?
        if not uuid in self.nodes:
            return
        
        node = self.nodes.get(uuid, None)
        # The node can vanish by another thread delete
        if node is None:
            return

        # Maybe we already know it's leaved, so don't update it
        if node['state'] == 'leave':
            return

        print "SET LEAVE %s and inner node %s" % (leaved, node)
        
        # If for me it must be with my own incarnation number so we are sure it's really us that should leave
        # and not 
        if uuid == self.uuid:
            if incarnation != node['incarnation']:
                print "LEAVE INCARNATION NOT THE SAME FOR MYSELF"
                return
        else:
            # If not for me, use the classic 'not already known' rule
            if incarnation < node['incarnation']:
                print "LEAVE, NOT FOR ME, THE INCARNATION NUMBER IS TOO OLD"
                return

        print "SET LEAVE UUID and SELF.UUID", uuid, self.uuid
        # Maybe it's us?? If so we must send our broadcast and exit in few seconds
        if uuid == self.uuid:
            logger.log('LEAVE: someone is asking me for leaving.', part='gossip')
            self.incarnation += 1
            node['incarnation'] = self.incarnation
            self.stack_leave_broadcast(node)
            def bailout_after_leave(self):
                logger.log('Bailing out in few seconds. I was put in leave state')
                time.sleep(10)
                logger.log('Exiting from a self leave message')
                self.interrupted = True
                
            threader.create_and_launch(bailout_after_leave, args=(self,))
            return

        logger.log('LEAVING: The node %s is leaving' % node['name'], part='gossip')
        # Ok it's definitivly someone else that is now suspected, update this, and update it :)
        node['incarnation'] = incarnation
        node['state'] = state
        node['leave_time'] = int(time.time())
        node['tags'] = tags
        node['services'] = services
        self.stack_leave_broadcast(node)
        


    # Someone suspect a node, so believe it
    def set_dead(self, suspect):
        addr = suspect['addr']
        port = suspect['port']
        name = suspect['name']
        incarnation = suspect['incarnation']
        uuid = suspect['uuid']
        tags = suspect.get('tags', [])
        services = suspect.get('services', {})                
        state = 'dead'
        
        # Maybe we didn't even have this nodes in our list?
        if not uuid in self.nodes:
            return
        
        node = self.nodes.get(uuid, None)
        # The node can vanish
        if node is None:
            return

        # Maybe this data is too old
        if incarnation < node['incarnation']:
            return

        # We only case about into about alive nodes, dead and suspect
        # are not interesting :)
        if node['state'] != 'alive':
            return
        
        # Maybe it's us?? We need to say FUCKING NO, I'm alive!!
        if uuid == self.uuid:
            logger.log('SUSPECT: SOMEONE THINK I AM SUSPECT, BUT I AM ALIVE', part='gossip')
            self.incarnation += 1
            node['incarnation'] = self.incarnation
            self.stack_alive_broadcast(node)
            return
        
        logger.log('DEAD: I put in dead node %s' % node['name'], part='gossip')
        # Ok it's definitivly someone else that is now suspected, update this, and update it :)
        node['incarnation'] = incarnation
        node['state'] = state
        node['suspect_time'] = int(time.time())
        node['tags'] = tags
        node['services'] = services
        self.stack_dead_broadcast(node)
        

    # Set alive a node we eart about. 
    # * It can be us if we allow the bootstrap node (only at startup).
    # * If strong it means we did the check, so we believe us :)
    def set_alive(self, node, bootstrap=False, strong=False):
        addr = node['addr']
        port = node['port']
        name = node['name']
        incarnation = node['incarnation']
        uuid = node['uuid']
        state = node['state'] = 'alive'
        tags = node.get('tags', [])

        # Maybe it's me? if so skip it
        if not bootstrap:
            if node['addr'] == self.addr and node['port'] == self.port:
                return
        
        # Maybe it's a new node that just enter the cluster?
        if uuid not in self.nodes:
            logger.log("New node detected", node, part='gossip')
            # Add the node but in a protected mode
            with self.nodes_lock:
                self.nodes[uuid] = node
            self.stack_alive_broadcast(node)
            return
            
        prev = self.nodes.get(uuid, None)
        # maybe the prev was out by another thread?
        if prev is None:
            return
        change = (prev['state'] != state)
        
        # If the data is not just new, bail out
        if not strong and incarnation <= prev['incarnation']:
            return

        logger.debug('ALIVENODE', name, prev['state'], state, strong, change, incarnation, prev['incarnation'], (strong and change), (incarnation > prev['incarnation']))
        # only react to the new data if they are really new :)
        if strong or incarnation > prev['incarnation']:
            # protect the nodes access with the lock so others threads are happy :)
            with self.nodes_lock:
                self.nodes[uuid] = node
            # Only broadcast if it's a new data from somewhere else
            if (strong and change) or incarnation > prev['incarnation']:
                logger.debug("Updating alive a node", prev, 'with', node)
                self.stack_alive_broadcast(node)


    def create_alive_msg(self, node):
        return {'type':'alive', 'name':node['name'], 'addr':node['addr'], 'port': node['port'], 'uuid':node['uuid'],
                'incarnation':node['incarnation'], 'state':'alive', 'tags':node['tags'], 'services':node['services']}


    def create_event_msg(self, payload):
        return {'type':'event', 'from':self.uuid, 'payload':payload, 'ctime':int(time.time()), 'eventid':uuid.uuid1().get_hex()}


    def create_suspect_msg(self, node):
        return {'type':'suspect', 'name':node['name'], 'addr':node['addr'], 'port': node['port'], 'uuid':node['uuid'],
                'incarnation':node['incarnation'], 'state':'suspect', 'tags':node['tags'], 'services':node['services']}


    def create_dead_msg(self, node):
        return {'type':'dead', 'name':node['name'], 'addr':node['addr'], 'port': node['port'], 'uuid':node['uuid'],
                'incarnation':node['incarnation'], 'state':'dead', 'tags':node['tags'], 'services':node['services']}


    def create_leave_msg(self, node):
        return {'type':'leave', 'name':node['name'], 'addr':node['addr'], 'port': node['port'], 'uuid':node['uuid'],
                'incarnation':node['incarnation'], 'state':'leave', 'tags':node['tags'], 'services':node['services']}


    def create_new_ts_msg(self, key):
        return {'type':'/ts/new', 'from':self.uuid, 'key':key}
    

    def stack_alive_broadcast(self, node):
        msg = self.create_alive_msg(node)
        b = {'send':0, 'msg':msg}
        self.broadcasts.append(b)
        # Also send it to the websocket if there
        self.forward_to_websocket(msg)
        return 


    def stack_event_broadcast(self, payload):
        msg = self.create_event_msg(payload)
        b = {'send':0, 'msg':msg}
        self.broadcasts.append(b)
        return 


    def stack_new_ts_broadcast(self, key):
        msg = self.create_new_ts_msg(key)
        b = {'send':0, 'msg':msg, 'tags':'ts'}
        self.broadcasts.append(b)
        return 
    
    
    def stack_suspect_broadcast(self, node):
        msg = self.create_suspect_msg(node)
        b = {'send':0, 'msg':msg}
        self.broadcasts.append(b)
        # Also send it to the websocket if there
        self.forward_to_websocket(msg)
        return b


    def stack_leave_broadcast(self, node):
        msg = self.create_leave_msg(node)
        b = {'send':0, 'msg':msg}
        self.broadcasts.append(b)
        # Also send it to the websocket if there
        self.forward_to_websocket(msg)
        return b


    def stack_dead_broadcast(self, node):
        msg = self.create_dead_msg(node)
        b = {'send':0, 'msg':msg}
        self.broadcasts.append(b)
        self.forward_to_websocket(msg)
        return b


    # Manage a udp message
    def manage_message(self, m):
        #print "MANAGE", m        
        t = m['type']
        if t == 'push-pull-msg':
            self.merge_nodes(m['nodes'])
        elif t == 'ack':
            logger.debug("GOT AN ACK?")
        elif t == 'alive':
            self.set_alive(m)
        elif t in ['suspect', 'dead']:
            self.set_suspect(m)
        # Where the fuck is 'dead'??? <--- TODO
        elif t =='leave':
            self.set_leave(m)
        elif t == 'event':
            self.manage_event(m)
        else:            
            logger.debug('UNKNOWN MESSAGE', m)


    def manage_event(self, m):
        eventid = m.get('eventid', '')
        payload = m.get('payload', {})
        # if bad event or already known one, delete it
        with self.events_lock:
            if not eventid or not payload or eventid in self.events:
                return
        # ok new one, add a broadcast so we diffuse it, and manage it
        b = {'send':0, 'msg':m}
        self.broadcasts.append(b)
        with self.events_lock:
            self.events[eventid] = m

        # I am the sender for this event, do not handle it
        if m.get('from', '') == self.uuid:
            return

        _type = payload.get('type', '')
        if not _type:
            return
        
        # If we got a libexec file update message, we append this path to the list 
        # libexec_to_update so a thread will grok the new version from KV
        if _type == 'libexec':
            path = payload.get('path', '')
            _hash = payload.get('hash', '')
            if not path or not _hash:
                return
            logger.debug('LIBEXEC UPDATE asking update for the path %s wit the hash %s' % (path, _hash), part='propagate')
            self.libexec_to_update.append((path, _hash))
        # Ok but for the configuration part this time
        elif _type == 'configuration':
            path = payload.get('path', '')
            _hash = payload.get('hash', '')
            if not path or not _hash:
                return
            if 'path' == 'local.json':
               # We DONT update our local.json file, it's purely local
               return
            logger.debug('CONFIGURATION UPDATE asking update for the path %s wit the hash %s' % (path, _hash), part='propagate')
            self.configuration_to_update.append((path, _hash))
        # Maybe we are ask to clean our configuration, if so launch a thread because we can't block this
        # thread while doing it
        elif _type == 'configuration-cleanup':
           threader.create_and_launch(self.do_configuration_cleanup, name='configuration-cleanup')
        else:
            logger.debug('UNKNOWN EVENT %s' % m)
            return

        
    # Look at the /kv/configuration/ entry, uncompress the json string
    # and clean old files into the configuration directory that is not in this list
    # but not the local.json that is out of global conf
    def do_configuration_cleanup(self):
       zj64 = self.get_key('__configuration')
       if zj64 is None:
          logger.log('WARNING cannot grok kv/__configuration entry', part='propagate')
          return
       zj = base64.b64decode(zj64)
       j = zlib.decompress(zj)
       lst = json.loads(j)
       logger.debug("WE SHOULD CLEANUP all but not", lst, part='propagate')
       local_files = [os.path.join(dp, f) 
                      for dp, dn, filenames in os.walk(os.path.abspath(self.configuration_dir))
                      for f in filenames]
       for fname in local_files:
          path = fname[len(os.path.abspath(self.configuration_dir))+1:]
          # Ok, we should not have the local.json entry, but even if we got it, do NOT rm it
          if path == 'local.json':
             continue
          if not path in lst:
             full_path = os.path.join(self.configuration_dir, path)
             logger.debug("CLEANUP we should clean the file", full_path, part='propagate')
             try:
                os.remove(full_path)
             except OSError, exp:
                logger.log('WARNING: cannot cleanup the configuration file %s (%s)' % (full_path, exp), part='propagate')
        

    # Someone send us it's nodes, we are merging it with ours
    def merge_nodes(self, nodes):
        to_del = []
        # Get a copy of self.nodes so we won't lock too much here
        mynodes = {}
        with self.nodes_lock:
            mynodes = copy.copy(self.nodes)
        for (k, node) in nodes.iteritems():
            # Maybe it's me? bail out
            if node['addr'] == self.addr and node['port'] == self.port:
                continue

            # Look if we got some duplicates, that got the same addr, but different 
            for (otherk, othern) in mynodes.iteritems():
                if node['addr'] == othern['addr'] and node['port'] == othern['port'] and otherk != k:
                    # we keep the newest incarnation
                    if node['incarnation'] < othern['incarnation']:
                        to_del.append(k)
                    else:
                        to_del.append(otherk)

            state = node['state']
                              
            # Try to incorporate it
            if state == 'alive':
                self.set_alive(node)
            elif state == 'dead' or state == 'suspect':
                self.set_suspect(node)
            elif state == 'leave':
                self.set_leave(node)

        # Now clean old nodes
        for k in to_del:
            try:
                del self.nodes[k]
            except KeyError:
                pass
            
        
    # We will choose a random guy in our nodes that is alive, and
    # sync with it
    def launch_full_sync(self):
        logger.debug("Launch_full_sync:: all nodes %d" % len(self.nodes), part='gossip')
        nodes = {}
        with self.nodes_lock:
            nodes = copy.copy(self.nodes)
        others = [ (n['addr'], n['port']) for n in nodes.values() if n['state'] == 'alive' and n['uuid'] != self.uuid]
        
        if len(others) >= 1:
            other = random.choice(others)
            logger.debug("launch_full_sync::", other, part='gossip')
            self.do_push_pull(other)
        #else:
        #    print "NO OTHER ALIVE NODES !"


    # We will choose some K random nodes and gossip them the broadcast messages to them
    def launch_gossip(self):
        # There is no broadcast message to sent so bail out :)
        if len(self.broadcasts) == 0:
            return
        
        ns = self.nodes.values()
        #ns.sort()
        logger.debug("launch_gossip:: all nodes %d" % len(self.nodes), part='gossip')
        others = [n for n in ns if n['uuid'] != self.uuid]
        # Maybe every one is dead, if o bail out
        if len(others) == 0:
            return
        nb_dest = min(len(others), KGOSSIP)
        dests = random.sample(others, nb_dest)
        for dest in dests:
            logger.debug("launch_gossip::", dest['name'], part='gossip')
            self.do_gossip_push(dest)

    
    # we ping some K random nodes, but in priority some nodes that we thouugh were deads
    # but talk to us
    # also exclude leave node, because thay said they are not here anymore ^^
    def ping_another(self):
        #print "PING ANOTHER"
        nodes = {}
        with self.nodes_lock:
            nodes = copy.copy(self.nodes)
        others = [ n for n in nodes.values() if n['uuid'] != self.uuid and n['state'] != 'leave']
        
        # first previously deads
        for uuid in self.to_ping_back:
            if uuid in nodes:
                self.do_ping(nodes[uuid])
        # now reset it
        self.to_ping_back = []

        # Now we take one in all the others
        if len(others) >= 1:
            other = random.choice(others)
            self.do_ping(other)


    # Launch a ping to another node and if fail set it as suspect
    def do_ping(self, other):
        ping_payload = {'type':'ping', 'seqno':0, 'node': other['name'], 'from': self.uuid}
        message = json.dumps(ping_payload)
        enc_message = self.encrypt(message)
        addr = other['addr']
        port = other['port']
        _t = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            sock.sendto(enc_message, (addr, port) )
            logger.debug('PING waiting %s ack message' % other['name'], part='gossip')
            # Allow 3s to get an answer
            sock.settimeout(3)
            ret = sock.recv(65535)
            logger.debug('PING got a return from %s' %  other['name'], len(ret), part='gossip')
            # An aswer? great it is alive!
            self.set_alive(other, strong=True)
        except socket.timeout, exp:
            logger.debug("PING: timeout joining the other node %s:%s : %s" % (addr, port, exp), part='gossip')
            logger.debug("PING: go indirect mode", part='gossip')
            possible_relays = []
            with self.nodes_lock:
                possible_relays = [n for n in self.nodes.values() if n['uuid'] != self.uuid and n != other and n['state'] == 'alive']

            if len(possible_relays) == 0:
                logger.log("PING: no possible relays for ping", part='gossip')
                self.set_suspect(other)
            # Take at least 3 relays to ask ping
            relays = random.sample(possible_relays, min(len(possible_relays), 3))
            logger.debug('POSSIBLE RELAYS', relays)
            ping_relay_payload = {'type':'ping-relay', 'seqno':0, 'tgt': other['uuid'], 'from': self.uuid}
            message = json.dumps(ping_relay_payload)
            enc_message = self.encrypt(message)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            for r in relays:
                try:
                    sock.sendto(enc_message, (r['addr'], r['port']) )
                    logger.debug('PING waiting ack message', part='gossip')
                except socket.error, exp:
                    logger.error('Cannot send a ping relay to %s:%s' % (r['addr'], r['port']), part='gossip')
            # Allow 3s to get an answer from whatever relays got it
            sock.settimeout(3*2)
            try:
                ret = sock.recv(65535)
            except socket.timeout:
                # still noone succed to ping it? I suspect it
                self.set_suspect(other)
                sock.close()
                return
            msg = json.loads(ret)
            sock.close()
            logger.debug('PING: got an answer from a relay', msg, part='gossip')
            logger.debug('RELAY set alive', other['name'], part='gossip')
            # Ok it's no more suspected, great :)
            self.set_alive(other, strong=True)
        except socket.error, exp:
            logger.log("PING: cannot join the other node %s:%s : %s" % (addr, port, exp), part='gossip')
        

    # Randomly push some gossip broadcast messages and send them to
    # KGOSSIP others nodes
    def do_gossip_push(self, dest):
        message = ''
        to_del = []
        stack = []
        tags = dest['tags']
        for b in self.broadcasts:
            # not a valid node for this message, skip it
            if 'tag' in b and b['tag'] not in tags:
                continue
            old_message = message
            send = b['send']
            if send >= KGOSSIP:
                to_del.append(b)
            bmsg = b['msg']
            stack.append(bmsg)
            message = json.dumps(stack)
            # Maybe we are now too large and we do not have just one
            # fucking big message, so we fail back to the old_message that was
            # in the good size and send it now
            if len(message) > 1400 and len(stack) != 1:
                message = old_message
                stack = stack[:-1]
                break
            # stack a sent to this broadcast message
            b['send'] += 1

        # Clean too much broadcasted messages
        for b in to_del:
            self.broadcasts.remove(b)
            
        # Void message? bail out
        if len(message) == 0:
            return

        addr = dest['addr']
        port = dest['port']
        # and go for it!
        try:
            enc_message = self.encrypt(message)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # UDP
            sock.sendto(enc_message, (addr, port) )
            logger.debug('BROADCAST: sent %d message (len=%d) to %s:%s' % (len(stack), len(enc_message), addr, port), part='gossip')
        except socket.timeout, exp:
            logger.debug("ERROR: cannot sent the message %s" % exp, part='gossip')
        try:
            sock.close()
        except Exception:
            pass


    # Will try to join a node cluster and do a push-pull with at least one of them
    def join(self):
        logger.log("We will try to join our seeds members", self.seeds, part='gossip')
        tmp = self.seeds
        others = []
        if not len(self.seeds):
            logger.log("No seeds nodes, I'm a bootstrap node?")
            return
        
        for e in tmp:
            elts = e.split(':')
            addr = elts[0]
            port = self.port
            if len(elts) > 1:
                port = int(elts[1])
            others.append( (addr, port) )
        random.shuffle(others)
        while True:
            logger.log('JOINING myself %s is joining %s nodes' % (self.name, others), part='gossip')
            nb = 0
            for other in others:
                nb += 1
                r = self.do_push_pull(other)
                
                # Do not merge with more than KGOSSIP distant nodes
                if nb > KGOSSIP:
                    continue
            # If we got enough nodes, we exit
            if len(self.nodes) != 1 or self.interrupted or self.bootstrap:
                return
            # Do not hummer the cpu....
            time.sleep(0.1)


    # Go launch a push-pull to another node. We will sync all our nodes
    # entries, and each other will be able to learn new nodes and so
    # launch gossip broadcasts if need
    def do_push_pull(self, other):
        nodes = {}
        with self.nodes_lock:
            nodes = copy.copy(self.nodes)
        m = {'type': 'push-pull-msg', 'nodes': nodes}
        message = json.dumps(m)
        
        (addr, port) = other
        
        uri = 'http://%s:%s/push-pull' % (addr, port)
        payload = {'msg': message}
        try:
           r = rq.get(uri, params=payload)
           logger.debug("push-pull response", r, part='gossip')
           try:
               back = json.loads(r.text)
           except ValueError, exp:
               logger.debug('ERROR CONNECTING TO %s:%s' % other, exp, part='gossip')
               return False
           self.manage_message(back)
           return True
        except rq.exceptions.RequestException,exp: #Exception, exp:
           logger.debug('ERROR CONNECTING TO %s:%s' % other, exp, part='gossip')
           return False

    
    # each second we look for all old events in order to clean and delete them :)
    def clean_old_events(self):
        now = int(time.time())
        to_del = []
        with self.events_lock:
            for (cid, e) in self.events.iteritems():
                ctime = e.get('ctime', 0)
                if ctime < now - self.max_event_age:
                    to_del.append(cid)
        # why sleep here? because I don't want to take the lock twice as quik is an udp thread
        # is also waiting for it, it is prioritary, not me
        time.sleep(0.01)
        with self.events_lock:
            for cid in to_del:
                try:
                    del self.events[cid]
                except IndexError: # if already delete, we don't care
                    pass
        
