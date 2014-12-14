#!/usr/bin/env python
import json
import time
import sys
try:
    from docker import Client
except ImportError:
    Client = None

from kunai.stats import STATS
from kunai.log import logger
from kunai.threadmgr import threader
from kunai.now import NOW

    
class DockerManager(object):
    def __init__(self):
        self.con = None
        self.containers = {}

        
    def launch(self):
        if not Client:
            logger.warning('Missing docker lib')
            return
        t = threader.create_and_launch(self.do_loop, name='docker-loop')


    def connect(self):
        if not self.con:
            try:
                self.con = Client(base_url='unix://var/run/docker.sock')
            except Exception, exp:
                logger.debug('Cannot connect to docker %s' % exp)
                self.con = None


    def load_container(self, _id):
        inspect = self.con.inspect_container(_id)
        c = {}
        # put in lower all keys
        for (k,v) in inspect.iteritems():
            c[k.lower()] = v
        logger.debug('LOADED NEW CONTAINER %s' % c)
        self.containers[_id] = c
        
    
    def load_containers(self):
        if not self.con:
            return
        conts = self.con.containers()
        for c in conts:
            _id = c.get('Id')
            self.load_container(_id)
            print "Container", self.containers[_id]
                
        
    def do_loop(self):
        self.connect()
        self.load_containers()
        while True:
            self.connect()
            if not self.con:
                time.sleep(1) # do not hammer the connexion
                continue
            # now manage events and lock on it
            evts = self.con.events() # can lock here
            for ev in evts:
                evdata = json.loads(ev)
                _id = evdata["id"]
                status = evdata["status"]
                if status in ("die", "stop"):
                    if _id in self.containers:
                        logger.debug('removing a container %s' % _id)
                        del self.containers[_id]
                    else:
                        logger.error('Asking to remove an unknow container? %s' % _id)
                elif status == 'start':
                    self.load_container(_id)
                else:
                    logger.debug('UNKNOWN EVENT IN DOCKER %s' % status)


dockermgr = DockerManager()
                    
