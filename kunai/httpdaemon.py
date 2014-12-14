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


# now singleton objects
from kunai.websocketmanager import websocketmgr
from kunai.broadcast import broadcaster


# We want the http daemon to be accessible from everywhere without issue
class EnableCors(object):
    name = 'enable_cors'
    api = 2
    
    def apply(self, fn, context):
        def _enable_cors(*args, **kwargs):
            # Set CORS headers
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, OPTIONS, DELETE, PATCH'
            response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, X-Shinken-Token'
            response.headers['Access-Control-Allow-Crendentials'] = 'true'
            if bottle.request.method != 'OPTIONS':
                # actual request; reply with the actual response
                return fn(*args, **kwargs)

        return _enable_cors

    


# This class is the http daemon main interface
# in a singleton mode so you can easily register new uri from other
# part of the code, mainly by adding new route to bottle
class HttpDaemon(object):
    def __init__(self):
        pass


    def run(self, addr, port):
        # First enable cors on all our calls
        bapp = bottle.app()
        bapp.install(EnableCors())

        # Will lock for in this
        run(host=addr, port=port, server='cherrypy', numthreads=64)# 256?

    # Some default URI    
    @error(404)
    def err404(error):
        return ''
        
    @route('/')
    def slash():
        return 'OK'

        


httpdaemon = HttpDaemon()

