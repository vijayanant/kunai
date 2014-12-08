import httplib # Used only for handling httplib.HTTPException (case #26701)
import os
import sys
import platform
import re
import urllib
import urllib2
import traceback
import time
from StringIO import StringIO
from multiprocessing import subprocess

from kunai.log import logger
from kunai.collector import Collector


class CpuStats(Collector):
    def launch(self):
        logger.debug('getCPUStats: start')

        cpuStats = {}

        if sys.platform == 'linux2':
            logger.debug('getCPUStats: linux2')

            headerRegexp = re.compile(r'.*?([%][a-zA-Z0-9]+)[\s+]?')
            itemRegexp = re.compile(r'.*?\s+(\d+)[\s+]?')
            valueRegexp = re.compile(r'\d+\.\d+')
            proc = None
            try:
                proc = subprocess.Popen(['mpstat', '-P', 'ALL', '1', '1'], stdout=subprocess.PIPE, close_fds=True)
                stats = proc.communicate()[0]

                if int(self.pythonVersion[1]) >= 6:
                    try:
                        proc.kill()
                    except Exception, e:
                        logger.debug('Process already terminated')

                stats = stats.split('\n')
                header = stats[2]
                headerNames = re.findall(headerRegexp, header)
                device = None

                for statsIndex in range(4, len(stats)): # skip "all"
                    row = stats[statsIndex]

                    if not row: # skip the averages
                        break

                    deviceMatch = re.match(itemRegexp, row)

                    if deviceMatch is not None:
                        device = 'CPU%s' % deviceMatch.groups()[0]

                    values = re.findall(valueRegexp, row.replace(',', '.'))

                    cpuStats[device] = {}
                    for headerIndex in range(0, len(headerNames)):
                        headerName = headerNames[headerIndex]
                        cpuStats[device][headerName] = values[headerIndex]

            except OSError, ex:
                # we dont have it installed return nothing
                return False

            except Exception, ex:
                if int(self.pythonVersion[1]) >= 6:
                    try:
                        if proc:
                            proc.kill()
                    except UnboundLocalError, e:
                        logger.debug('Process already terminated')
                    except Exception, e:
                        logger.debug('Process already terminated')

                logger.error('getCPUStats: exception = %s', traceback.format_exc())
                return False
        else:
            logger.debug('getCPUStats: unsupported platform')
            return False

        logger.debug('getCPUStats: completed, returning')
        return cpuStats

