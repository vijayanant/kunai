import platform
import traceback
import subprocess
from collections import defaultdict

from kunai.stats import STATS
from kunai.log import logger
from kunai.threadmgr import threader
from kunai.now import NOW


pythonVersion = platform.python_version_tuple()
python24 = platform.python_version().startswith('2.4')


class Collector:
    class __metaclass__(type):
        __inheritors__ = set()
        def __new__(meta, name, bases, dct):
            klass = type.__new__(meta, name, bases, dct)
            meta.__inheritors__.add(klass)
            return klass

    @classmethod
    def get_sub_class(cls):        
        return cls.__inheritors__

    
    def __init__(self, config):
        self.config = config
        self.pythonVersion = pythonVersion
        
        self.mysqlConnectionsStore = None
        self.mysqlSlowQueriesStore = None
        self.mysqlVersion = None
        self.networkTrafficStore = {}
        self.nginxRequestsStore = None
        self.mongoDBStore = None
        self.apacheTotalAccesses = None
        self.plugins = None
        self.topIndex = 0
        self.os = None
        self.linuxProcFsLocation = None


    # Execute a shell command and return the result or '' if there is an error
    def execute_shell(self, cmd):
        # Get output from a command
        logger.debug('execute_shell:: %s' % cmd)
        output = ''
        try:
            try:
                proc = subprocess.Popen(cmd.split(' '), stdout=subprocess.PIPE, close_fds=True)
                output, err = proc.communicate()
                if int(pythonVersion[1]) >= 6:
                    try:
                        proc.kill()
                    except Exception, e:
                        pass
                if err:
                    logger.error('Error in sub process', err)

            except Exception, e:
                logger.error('execute_shell exception = %s', traceback.format_exc())
                return False

        finally:
            if int(pythonVersion[1]) >= 6:
                try:
                    proc.kill()
                except Exception, e:
                    #logger.debug('Process already terminated')
                    pass
            return output


    # from a dict recursivly build a ts
    # 'bla':{'foo':bar, 'titi': toto} => bla.foo.bar bla.titi.toto
    def create_ts_from_data(self, d, l, s):
        #print 'Create ts from data', d
        if not isinstance(d, dict):
            if isinstance(d, basestring):
                #print "REFUSING BAD VALUE", d
                return
            if isinstance(d, float) or isinstance(d, int):
                #print "FINISH HIM!"
                _t = l[:]
                #_t.append(d)
                _nts = '.'.join(_t)#ts, d)
                nts = '%s %s' % (_nts, d)
                s.add(nts)
            return
        # For each key,
        for (k,v) in d.iteritems():
            nl = l[:] # use a copy to l so it won't be overwriten
            nl.append(k)
            self.create_ts_from_data(v, nl, s)
            
        
        

    def main(self):
        logger.debug('Launching main for %s' % self.__class__)
        try:
            r = self.launch()
        except Exception, exp:
            logger.error('Collector %s main error: %s' (self.__class__.__name__.lower(), traceback.format_exc()))
            return
        #logger.debug('COLRESULT', r, self.__class__.__name__.lower())
        s = set()
        self.create_ts_from_data(r, [], s)
        print "TSS=", s
        
