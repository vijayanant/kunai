import threading
import ctypes
import traceback
import cStringIO

from kunai.log import logger

# this part is doomed for windows portability, will be fun to manage :)
try:
    libc = ctypes.CDLL('libc.so.6')
except Exception:
    libc = None



class ThreadMgr(object):
    def __init__(self):
        self.all_threads = []


    def check_alives(self):
        self.all_threads = [t for t in self.all_threads if t.is_alive()]


    def create_and_launch(self, f, args=(), name='unamed-thread'):
        def w():
            tid = 0
            if libc:
                tid = libc.syscall(186) # get the threadid when you are in it :)
            logger.info('THREAD launch (%s) with thread id (%d)' % (name, tid))
            try:
                f(*args)
            except Exception, exp:
                output = cStringIO.StringIO()
                traceback.print_exc(file=output)
                logger.error("Thread %s is exiting on error. Back trace of this error: %s" % (name, output.getvalue()))
                output.close()

        # Create a daemon thread with our wrapper function that will manage initial logging
        # and exception catchs
        t = threading.Thread(None, target=w, name=name)
        t.daemon = True
        t.start()
        self.all_threads.append(t)
        return t


threader = ThreadMgr()
