
import os
import copy
import traceback
import subprocess
try:
    import jinja2
except ImportError:
    jinja2 = None

'''
f = open('/root/kunai/etc/templates/haproxy.cfg')
buf = f.read()
f.close()

t = jinja2.Template(buf)

s = t.render(service=service, nodes=nodes, node=node)
'''

from kunai.log import logger


class Generator(object):
    def __init__(self, g):
        self.g = g
        print "LAUNCHING"*10, g
        self.buf = None
        self.template = None
        self.output = None

        
    # Open the template file and generate the output
    def generate(self, clust):
        # If not jinja2, bailing out
        if jinja2 is None:
            return
        try:
            f = open(self.g['template'], 'r')
            self.buf = f.read()
            f.close()
        except IOError, exp:
            logger.error('Cannot open template file %s : %s' % (self.g['template'], exp))
            self.buf = None
            self.template = None

        # Now try to make it a jinja template object
        try:
            self.template = jinja2.Template(self.buf)
        except Exception, exp:
            logger.error('Template file %s did raise an error with jinja2 : %s' % (self.g['template'], exp))
            self.buf = None
            self.template = None

        # Now try to render all of this with real objects
        try:
            # copy objects because they can move
            node = copy.copy(clust.nodes[clust.uuid])
            with clust.gossip.nodes_lock:
                nodes = copy.copy(clust.nodes) # just copy the dict, not the nodes themselves
            self.output = self.template.render(nodes=nodes, node=node)
        except Exception, exp:
            logger.error('Template rendering %s did raise an error with jinja2 : %s' % (self.g['template'], traceback.format_exc()))
            self.output = None
            self.template = None
            self.buf = None

            
    # If we did generate, try to see if we must write the file, and if so we will have to
    # launch the command
    def write_if_need(self):
        # Maybe there is no output, if so bail out now :)
        if self.output is None:
            return False

        self.cur_value = ''
        # first try to load the current file if exist and compare to the generated file
        if os.path.exists(self.g['path']):
            try:
                f = open(self.g['path'], 'r')
                self.cur_value = f.read()
                f.close()
            except IOError, exp:
                logger.error('Cannot open path file %s : %s' % (self.g['path'], exp))
                self.output = None
                self.template = ''
                self.buf = ''
                return False
        # If not exists or the value did change, regenerate it :)
        if not os.path.exists(self.g['path']) or self.cur_value != self.output:
            logger.debug('Generator %s generate a new value, writing it to %s' % (self.g['name'], self.g['path']))
            try:
                f = open(self.g['path'], 'w')
                f.write(self.output)
                f.close()
                logger.log('Generator %s did generate a new file at %s' % (self.g['name'], self.g['path']))
                return True
            except IOError, exp:
                logger.error('Cannot write path file %s : %s' % (self.g['path'], exp))
                self.output = None
                self.template = ''
                self.buf = ''
                return False

    # If need launch the restart command, shoul not block too long of
    # course
    def launch_command(self):
        cmd = self.g['command']
        try:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, preexec_fn=os.setsid)
        except Exception, exp:
            logger.error('Generator %s command launch (%s) fail : %s' % (self.g['name'], cmd, exp))
        output, err = p.communicate()
        rc = p.returncode
        if rc != 0:
            logger.error('Generator %s command launch (%s) error (rc=%s): %s' % (self.g['name'], cmd, rc, '\n'.join([output, err])))
            return
        logger.debug("Generator %s command succeded" % self.g['name'])

        
            
