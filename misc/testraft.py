import threading
import time
import random
import json
import math
import sys
import os
from Queue import Queue,Empty


#ELECTION_TIMEOUT_LIMITS = (150, 300)

HEARTHBEAT_INTERVAL = 150

ELECTION_PERIOD = 1000 # 1s for a candidate to wait for others response


class RaftNode(object):
    def __init__(self, i):
        self.i = i
        self.raft_state = 'follower'
        self.term = 0
        
        self.HEARTHBEAT_TIMEOUT = 1000
        self.ELECTION_TIMEOUT_LIMITS = (150, 300)
        
        self.leader = None
        # inner state that vary between :
        # follower=>wait_for_candidate=>candidate=>leader
        #                             =>did_vote
        
        self.state = 'follower'
        
        # some various timers
        self.t_to_candidate = 0
        
        # get the number of vote we have
        self.nb_vote = 0
        
        # and the election turn we have. This will increase the
        # election_timeout when we go in candidate state
        self.election_turn = 0
        
        

    def __str__(self):
        return '(%d:%s)' % (self.i, self.state)


    def tick(self, nodes):
        pass


    def give_vote_to(self, nodes, candidate_id):
        for d in nodes:
            if d['node'].i == candidate_id:
                m_ret = {'type':'vote', 'from':self.i}
                d['queue'].put(m_ret)

                
    def manage_ask_vote(self, m, nodes):
        if self.leader == None and self.state in ['follower', 'wait_for_candidate']: # no leader? ok vote for you guy! 
            #print "I give", m['candidate'], " my vote", self.i
            self.state = 'did-vote'
            candidate_id = m['candidate']
            self.give_vote_to(nodes, candidate_id)
        

    def manage_vote(self, m, nodes):
        if self.state != 'candidate': # exit if not already a candidate because
            return

        self.nb_vote += 1
        quorum_size = math.ceil(float(len(nodes)+1)/2)
        #print "I (%d) got a new voter %d" % (n.i, self.nb_vote)
        if self.nb_vote >= quorum_size:
            print "I (%d) did win the vote! with %d" % (self.i, self.nb_vote)
            self.state = 'leader'
            # warn every one that I am the leader
            for d in nodes:
                other = d['node']
                if other.i != self.i:
                    #print "I (%d) ASK %d for vote for me :) " % (n.i, other.i)
                    m_broad = {'type':'leader-elected', 'leader':self.i}
                    d['queue'].put(m_broad)


    # A new leader is elected, take it
    def manage_leader_elected(self, m, nodes):
        elected_id = m['leader']
        if elected_id == self.i:
            # that's me, I alrady know about it...
            return
        if self.state == 'leader': # another leader?
            print "TO MANAGE"*100
        elif self.state in ['candidate', 'follower', 'did-vote']: # 
            self.leader = None
            for d in nodes:
                if d['node'].i == elected_id:
                    self.leader = d['node']
            self.nb_vote = 0
            self.state = 'follower'
            self.t_to_candidate = 0
            if self.state == 'candidate':
                print "I (%d) got a new leader (%d) before me, and I respect it" % (self.i, self.leader.i)


    def look_for_candidated(self, nodes):
        if time.time() > self.t_to_candidate:
            print "N %d is going to be a candidate!" % self.i
            self.state = self.raft_state = 'candidate'
            self.nb_vote = 1 # I vote for me!
            possible_voters = nodes[:]
            random.shuffle(possible_voters) # so not every one is asking the same on the same time
                    
            for d in possible_voters:
                other = d['node']
                if other.i != self.i:
                    #print "I (%d) ASK %d for vote for me :) " % (n.i, other.i)
                    m = {'type':'ask-vote', 'candidate':self.i}
                    d['queue'].put(m)


    # We did fail to elect someone, so we increase the election_turn
    # so we will wait more for being candidate.
    # also reset the states
    def fail_to_elect(self):
        self.election_turn += 1
        self.reset()
        
        
    # Get back to default values for vote things :)
    def reset(self):
        self.nb_vote = 0
        self.state = 'follower'
        self.t_to_candidate = 0

        
                                    
    def node_main(self, q, nodes):
        time.sleep(2)
        start = time.time()

        n = self

        #print "Go run node", n.i, n.state
        #print 'All nodes', ','.join([str(e['node']) for e in nodes])
        #print n
        
        while time.time() < start + (self.HEARTHBEAT_TIMEOUT/1000.0)*2:            
            # look for message before looking for a new state :)
            try:
                r = q.get_nowait()
            except Empty:
                r = ''
            if r:
                m = r

                #print " %d I got a message: %s" % (n.i, m)
                
                # Someone ask us for voting for them. We can only if we got no valid leader
                # and we are a follower or not until a candidate
                if m['type'] == 'ask-vote':
                    self.manage_ask_vote(m, nodes)
                if m['type'] == 'vote': # someone did vote for me?
                    self.manage_vote(m, nodes)
                # someone win the match, respect it                                
                if m['type'] == 'leader-elected':
                    self.manage_leader_elected(m, nodes)

                # loop as fast as possible to get a new message now
                continue
            
            if self.leader == None and self.state == 'follower':
                low_election_timeout, high_election_timout = self.ELECTION_TIMEOUT_LIMITS
                #print "INCREASING LOOP", 2**self.election_turn, high_election_timout * (2**self.election_turn)
                #if high_election_timout > self.HEARTHBEAT_TIMEOUT:
                #    print 'WARNING, your election timeout is getting too high to be viable'
                    #high_election_timout = self.HEARTHBEAT_TIMEOUT
                    #os._exit(2)
                
                # ask for a timeout between 150 and 300ms                    
                election_timeout = random.randint(low_election_timeout, high_election_timout) * 0.001 
                self.t_to_candidate = time.time() + election_timeout
                self.state = 'wait_for_candidate'
            
            elif self.state == 'wait_for_candidate':
                self.look_for_candidated(nodes)
            
            time.sleep(0.01)




N = 500

nodes = [{'node':RaftNode(i), 'queue': Queue()} for i in range(N)]

def do_the_job(LOOP):
    #nodes = [{'node':RaftNode(i), 'queue': Queue()} for i in range(N)]

    threads = []
    for d in nodes:
        n = d['node']
        q = d['queue']
        t = threading.Thread(None, target=n.node_main, name='node-%d' % n.i, args=(q, nodes))
        t.daemon = True
        t.start()
        threads.append(t)

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



LOOP = 0
while True:
    LOOP += 1
    # Start with basic election
    do_the_job(LOOP)
    for d in nodes:
        n = d['node']
        n.fail_to_elect()
        
