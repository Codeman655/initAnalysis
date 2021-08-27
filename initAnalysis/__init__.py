#!/usr/bin/env python3


# ************************************
# InitAnalysis Graph Tool
# The chain of events is as follows:
# 
#  * The kernel looks in several places for init and runs the first one it finds
#  * init runs /etc/rc.d/rc.sysinit
#  * rc.sysinit does a bunch of necessary things and then runs rc.serial (if it exists)
#  * init runs all the scripts for the default runlevel.
#  * init runs rc.local 
# 
# SystemV source: https://www.linux.co.cr/distributions/review/1997/red-hat-5.0/doc081.html
# written by: craigca@ornl.gov
# ************************************

import sys,os,argparse,stat,subprocess,copy
import logging
import csv
import pprint 
import re

import magic
import networkx as nx

from .InitAnalysis import * #InitAnalysis and FileRecord classes
