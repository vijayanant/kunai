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
from kunai.httpdaemon import route, response


def lower_dict(d):    
    nd = {}
    for k,v in d.iteritems():
        nk = k.lower()
        if isinstance(v, dict): # yes, it's recursive :)
            v = lower_dict(v)
        nd[nk] = v
    return nd


class DockerManager(object):
    def __init__(self):
        self.con = None
        self.containers = {}
        # We got an object, we can fill the http daemon part
        self.export_http()

        
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
        c = lower_dict(inspect)
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

                    
    # main method to export http interface. Must be in a method that got
    # a self entry
    def export_http(self):

        @route('/docker/')
        @route('/docker')
        def get_docker():
            response.content_type = 'application/json'
            return json.dumps(self.con is not None)
    

        @route('/docker/containers')
        @route('/docker/containers/')
        def get_containers():
            response.content_type = 'application/json'
            return json.dumps(self.containers.values())

        
        @route('/docker/containers/:_id')
        def get_container(_id):
            response.content_type = 'application/json'
            cont = self.containers.get(_id, None)
            return json.dumps(cont)
    

        @route('/docker/images')
        @route('/docker/images/')
        def get_images():
            response.content_type = 'application/json'
            if self.con is None:
                return json.dumps(None)
            imgs = self.con.images()
            r = [lower_dict(d) for d in imgs]
            return json.dumps(r)

        
        @route('/docker/images/:_id')
        def get_images(_id):
            response.content_type = 'application/json'
            if self.con is None:
                return json.dumps(None)
            imgs = self.con.images()
            for d in imgs:
                if d['Id'] == _id:
                    return json.dumps(lower_dict(d))
            return json.dumps(None)

                    

dockermgr = DockerManager()
                    
