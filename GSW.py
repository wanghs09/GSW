#!/usr/bin/python
import math
import collections
import random
import sys
import numpy as np
from GSWfun import *
#import dask.array as da
#import toolz
import pickle
import glob, os


random.seed(2016)


if __name__ == '__main__':
	if len(sys.argv) < 2:
        note()
    else:
    	tgt = sys.argv[1]
    	if tgt == 'reGen'
    		map(os.remove, glob.glob('cipher*'))
			map(os.remove, glob.glob('int*'))
    		params_write(L)
    					

    	elif tgt == '00': 
    		HE_bin_fun()
    	elif tgt == '01': 
    		HE_int_fun()
    	elif tgt == '10': #pre-calculation for encrypted weights and enrypt integers
    		HE_int_fun_Asiacrypt(0)
		elif tgt == '11': 
			HE_int_fun_Asiacrypt(1)

