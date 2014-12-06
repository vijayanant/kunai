import threading
import time
import random
import json
import math
import sys
import os
from Queue import Queue,Empty


ELECTION_TIMEOUT_LIMITS = (150, 300)
#ELECTION_TIMEOUT_LIMITS = (4800, 9000)
HEARTHBEAT_INTERVAL = 150
HEARTHBEAT_TIMEOUT = 1000

ELECTION_PERIOD = 1000 # 1s for a candidate to wait for others response


class RaftNode(object):
    def __init__(self, i):
        self.i = i
        self.raft_state = 'follower'
        self.term = 0
        
        self.leader = None
        # inner state that vary between :
        # follower=>wait_for_candidate=>candidate
        #                             =>did_vote
        
        self.state = 'follower'

        # some various timers
        self.t_to_candidate = 0

        # get the number of vote we have
        self.nb_vote = 0


    def __str__(self):
        return '(%d:%s)' % (self.i, self.state)



    def tick(self, nodes):
        pass
    

def node_main(n, q, nodes):
    time.sleep(2)
    start = time.time()
    
    start_of_leader = 0.0
    election_timeout = 0
    
    #print "Go run node", n.i, n.state
    #print 'All nodes', ','.join([str(e['node']) for e in nodes])
    #print n

    while time.time() < start + (HEARTHBEAT_TIMEOUT/1000.0)*2:
        # look for message before looking for a new state :)
        try:
            r = q.get_nowait()
        except Empty:
            r = ''
        if r:
            m = r#json.loads(r)
            
            #print " %d I got a message: %s" % (n.i, m)
            # manage this message and skip this loop after this
            if m['type'] == 'ask-vote':
                if n.leader == None and n.state in ['follower', 'wait_for_candidate']: # no leader? ok vote for you guy! 
                    #print "I give", m['candidate'], " my vote", n.i
                    n.state = 'did-vote'
                    candidate_id = m['candidate']
                    for d in nodes:
                        if d['node'].i == candidate_id:
                            m_ret = {'type':'vote', 'from':n.i}
                            d['queue'].put(m_ret)#json.dumps(m_ret))
            
            if m['type'] == 'vote': # someone did vote for me?
                if n.state == 'candidate': # cool, I was really a candidate :)
                    n.nb_vote += 1
                    quorum_size = math.ceil(float(len(nodes)+1)/2)
                    #print "I (%d) got a new voter %d" % (n.i, n.nb_vote)
                    if n.nb_vote >= quorum_size:
                        print "I (%d) did win the vote! with %d" % (n.i, n.nb_vote)
                        n.state = 'leader'
                        print "WIN IN", time.time() - start, time.time() - start_of_leader, election_timeout, ELECTION_TIMEOUT_LIMITS
                        # warn every one that I am the leader
                        for d in nodes:
                            other = d['node']
                            if other.i != n.i:
                                #print "I (%d) ASK %d for vote for me :) " % (n.i, other.i)
                                m_broad = {'type':'leader-elected', 'leader':n.i}
                                d['queue'].put(m_broad)#json.dumps(m))
            
            # someone win the match, respect it                                
            if m['type'] == 'leader-elected':
                elected_id = m['leader']
                if elected_id == n.i:
                    # that's me, I alrady know about it...
                    continue
                if n.state == 'leader': # another leader?
                    print "TO MANAGE"*100
                elif n.state in ['candidate', 'follower', 'did-vote']: # 
                    n.leader = None
                    for d in nodes:
                        if d['node'].i == elected_id:
                            n.leader = d['node']
                    n.nb_vote = 0
                    n.state = 'follower'
                    n.t_to_candidate = 0
                    if n.state == 'candidate':
                        print "I (%d) got a new leader (%d) before me, and I respect it" % (n.i, n.leader.i)
                    # for the example don't go too far
                    break
            continue

        if n.leader == None and n.state == 'follower':
            low_election_timeout, high_election_timout = ELECTION_TIMEOUT_LIMITS
            #if high_election_timout > HEARTHBEAT_TIMEOUT:
            #    print 'WARNING, your election timeout is getting too high to be viable'
                #high_election_timout = HEARTHBEAT_TIMEOUT
                #os._exit(2)
            election_timeout = random.randint(low_election_timeout, high_election_timout) * 0.001 # ask for a timeout between 150 and 300ms
            n.t_to_candidate = time.time() + election_timeout
            n.state = 'wait_for_candidate'
            #print "N %d will be a candidate in %f" % (n.i, election_timeout), ELECTION_TIMEOUT_LIMITS, low_election_timeout, high_election_timout
        elif n.state == 'wait_for_candidate':
            if time.time() > n.t_to_candidate:
                print "N %d is going to be a candidate!" % n.i
                n.state = n.raft_state = 'candidate'
                n.nb_vote = 1 # I vote for me!
                start_of_leader = time.time()
                possible_voters = nodes[:]
                random.shuffle(possible_voters) # so not every one is asking the same on the same time
                #st = (random.random()*0.04) #20ms
                #time.sleep(st)
                
                for d in possible_voters:
                    other = d['node']
                    if other.i != n.i:
                        #print "I (%d) ASK %d for vote for me :) " % (n.i, other.i)
                        m = {'type':'ask-vote', 'candidate':n.i}
                        d['queue'].put(m)#json.dumps(m))

        time.sleep(0.01)




N = 300


def do_the_job():
    nodes = [{'node':RaftNode(i), 'queue': Queue()} for i in range(N)]

    threads = []
    for d in nodes:
        n = d['node']
        q = d['queue']
        t = threading.Thread(None, target=node_main, name='node-%d' %n.i, args=(n, q, nodes))
        t.daemon = True
        t.start()
        threads.append(t)


    for t in threads:
        t.join()

    # did we got a leader?
    print "RESULT FOR", ELECTION_TIMEOUT_LIMITS, LOOP
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

    print "Candidate density::", LOOP, ELECTION_TIMEOUT_LIMITS[1] / float(N), "ms", "& number of candidate in this loop (%d)" % LOOP, len([d for d in nodes if d['node'].state in ('candidate', 'leader')])
    if leader is not None:
        print "Good job jim", "LOOP", LOOP
        sys.exit(0)

    print "No leader, max vote is", max_vote



LOOP = 0
while True:
    LOOP += 1
    # Start with basic election
    do_the_job()
    ELECTION_TIMEOUT_LIMITS = (ELECTION_TIMEOUT_LIMITS[0], ELECTION_TIMEOUT_LIMITS[1]*2)
