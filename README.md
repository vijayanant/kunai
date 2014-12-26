Kunai
======

This is a **preview** of the kunai project about a service discovery / monitoring / light cfg management / command execution tool.

[![Build Status](https://travis-ci.org/naparuba/kunai.svg)](https://travis-ci.org/naparuba/kunai)


Prereqs
========

You will need:

  * python >= 2.6 (but not 3)
  * python-leveldb
  * python-requests


Quik and dirty 
==============

You need to create the directories:

   /var/lib/kunai/data
   /var/lib/kunai/libexec/

and copy the cli directory into the /var/lib/kunai/


First launch
============

You can quick launch manually your daemon with:

   python tanuki.py

(a real launcher will be available soon)


And check that the 6768 port is open (http)


Is there an UI?
===============

Yes. There is a (simple) UI available in the ui/ directory. It's just flat file and so you can just export the directory with apache/nginx and play with it.


How to add new nodes in the node cluster?
=========================================

First you need to install and launch the node in another server.

Then in this other server you can launch:
  
   bin/kunai join  OTHER-IP:6768

You can list the cluster members on all nodes with :

  bin/kunai  members

And you will see the new node on the UI.

