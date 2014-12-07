import httplib # Used only for handling httplib.HTTPException (case #26701)
import os
import platform
import re
import urllib
import urllib2
import traceback
import time
from StringIO import StringIO


from kunai.log import logger
from kunai.collector import Collector


class LoadAverage(Collector):
    def launch(self):
        logger.debug('getLoadAvrgs: start')

        # Get the triplet from the python function
        try:
            loadAvrgs_1, loadAvrgs_5, loadAvrgs_15 = os.getloadavg()
        except OSError:
            # If not available, return nothing
            return False
        
        logger.debug('getLoadAvrgs: parsing')

        loadAvrgs = {'1': loadAvrgs_1, '5': loadAvrgs_5, '15': loadAvrgs_15}
        
        logger.debug('getLoadAvrgs: completed, returning')

        return loadAvrgs
