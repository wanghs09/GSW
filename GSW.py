#!/usr/bin/python
from GSWfun import *
import glob, os
#import scipy


if __name__ == '__main__':
	if len(sys.argv) < 2:
		note()
	else:
		tgt = sys.argv[1]
		ini()

		if tgt == 'reGen':	#regeneration parameters					
			params_write(L) 					
		elif tgt == 'bin0': #homo binary functions
			HE_bin_fun()
		elif tgt == 'int1': #homo integer functions 
			HE_int_fun()
		elif tgt == 'ac0': #pre-calculation for encrypted weights and enrypt integers
			HE_int_fun_Asiacrypt(0)
		elif tgt == 'ac1': #homo Asiacrypt way functions
			HE_int_fun_Asiacrypt(1)

		elif tgt == '20': #
			HE_ext_bit()

		elif tgt == 'Gq':
			Gq_test_fun()

		else:
			print "wrong input!"

