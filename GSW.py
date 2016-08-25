#!/usr/bin/python
from GSWfun import *
import glob, os

if __name__ == '__main__':
	if len(sys.argv) < 2:
		note()
	else:
		tgt = sys.argv[1]
		ini()

		if tgt == 'reGen':						
			params_write(L) 					
		elif tgt == '00': 
			HE_bin_fun()
		elif tgt == '01': 
			HE_int_fun()
		elif tgt == '10': #pre-calculation for encrypted weights and enrypt integers
			HE_int_fun_Asiacrypt(0)
		elif tgt == '11': 
			HE_int_fun_Asiacrypt(1)

		elif tgt == '20':
			HE_ext_bit()

		elif tgt == 'Gq':
			Gq_test_fun()

		else:
			print "wrong input!"

