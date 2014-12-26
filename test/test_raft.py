#!/usr/bin/env python
# Copyright (C) 2014:
#    Gabes Jean, naparuba@gmail.com

import copy
import time
import threading
from Queue import Queue,Empty

from kunai_test import *
from kunai.raft import RaftNode


class TestRaft(KunaiTest):
    def setUp(self):
        pass

    def create(self, N=3):
        self.nodes = [{'node':RaftNode(i), 'queue': Queue()} for i in range(N)]
        
        
    def launch(self):
        #nodes = [{'node':RaftNode(i), 'queue': Queue()} for i in range(N)]

        self.threads = []
        for d in self.nodes:
            n = d['node']
            q = d['queue']
            t = threading.Thread(None, target=n.main, name='node-%d' % n.i, args=(q, self.nodes))
            t.daemon = True
            t.start()
            self.threads.append(t)

        self.start = time.time()

        return

    
        for t in threads:
            t.join()

        # did we got a leader?
        print "RESULT FOR", LOOP
        leader = None
        max_vote = 0
        for d in nodes:
            n = d['node']
            max_vote = max(max_vote, n.nb_vote)
            if n.state == 'leader':
                if leader != None:
                    print "WE GOT 2 LEADER, WTF DID YOU DID JEAN?????"
                    sys.exit("JEAN HOW CAN YOU BREAK SUCH AN ALGO?")

                print "GOT A LEADER", n.i, 'with ', n.nb_vote, "LOOP", LOOP
                leader = n

        print "Candidate density::", LOOP, 300*(2**LOOP) / float(N), "ms", "& number of candidate in this loop (%d)" % LOOP, len([d for d in nodes if d['node'].state in ('candidate', 'leader')])
        if leader is not None:
            print "Good job jim", "LOOP", LOOP
            sys.exit(0)

        print "No leader, max vote is", max_vote


    def stop(self):
        for d in self.nodes:
            n = d['node']
            n.stop()
        for t in self.threads:
            t.join(2)


    def test_raft_simple_leader_election(self):
        self.create_and_wait(N=3, wait=3)
        print self.nodes
        leaders = []
        for d in self.nodes:
            n = d['node']
            print n.state
            if n.state == 'leader':
                leaders.append(n)

        print "Looking if we really got a leader, and only one"
        self.assert_(len(leaders) == 1)
        
        self.stop()
        
            

    # Create N nodes with their own thread, and wait some seconds 
    def create_and_wait(self, N=3, wait=3):
        self.create(3)
        self.launch()
        time.sleep(wait)

        
if __name__ == '__main__':
    unittest.main()
