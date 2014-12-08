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
                print 'PROC', proc
                output, err = proc.communicate()
                if int(pythonVersion[1]) >= 6:
                    try:
                        proc.kill()
                    except Exception, e:
                        logger.debug('Process already terminated')
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
                    logger.debug('Process already terminated')
            return output


    def main(self):
        logger.debug('Launching main for %s' % self.__class__)
        r = self.launch()
        logger.debug('COLRESULT', r, self.__class__.__name__.lower())
    
