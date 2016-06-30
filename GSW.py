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

'''
origin = sys.stdout
fp=open('vectors.txt','w')
sys.stdout = fp
'''

#parameters from shield
random.seed(2016)


#GSW
#security level
lm=80

#level of circuits
L=10 

#pre-calculation for parameters and encrypted weights
'''
params_write(L)
wt_lst=[]
for i in range(0, params.ell-1): #less than 2**(ell-1)
	wt_lst.append("w"+str(i))
	BM_PlainEnc(params, 2**i, key, wt_lst[i])
'''

params,key=params_read()
print params

wt_lst=[]
for i in range(0, params.ell-1): #less than 2**(ell-1)
	wt_lst.append("w"+str(i))

#tst(params)
#test_table()

#print dec_to_bin(11,6)
#binary homo calcualtions

file1='tb.data1'
file2='tb.data2'
file3='tb.data3'

#ciphertext file
Cfile ='cipher'
Cfile1='cipher1'
Cfile2='cipher2'
Cfile3='cipher3'
Cfile_end='ciphere'#end file

#homomorphic integer, Asiacrypt way
#plaintext_lst=[12 78 78] #7-bit
#BM_PlainEnc(params, 2**i, key, wt_lst[i])
#BM_MPDec(params,wt_lst[i],key)

#h5file1 = tb.open_file('int0')


#pre-encryptions
pnum=6
psize=7
flst_pfx='int_'

flst=[]
for i in range(0, pnum): 
	flst.append([])
	for j in range(0, psize): 
		flst[i].append(flst_pfx+str(i)+'_'+str(j))

'''
map(os.remove, glob.glob('cipher*'))
map(os.remove, glob.glob('int*'))

#initial ciphertext
BM_SecEnc(params, 1, key, Cfile1)

#encrypt all integers to a ciphertext vector
int_lst=[np.random.random_integers(1,2**psize) for i in range(pnum)]  

print int_lst
#[37, 15, 45, 86, 127, 98]
#noise simulation, Jun 13
round 1
tmp=11274, noise=12070, m=555
round 2
tmp=38760, noise=39412, m=24975
round 3
tmp=-112937, noise=115115, m=2147850
round 4
tmp=-547513, noise=547513, m=272776950
round 5 # overflow, plaintext size>2**31
tmp=-253696, noise=844319, m=962337324

for i in range(0, pnum): 
	BM_SecEnc_int_Asiacrypt(int_lst[i], flst[i], key, params, psize) #filename = 'int_integer name_weight'
print 'Encryption finished!'
'''

fr='intr6'
for i in range(1, pnum):
	print 'round '+str(i)
	fr=BM_mult_int_Asiacrypt(fr, flst[i], wt_lst, params,32, psize) #11 is the max size of 1234, since 1234<2**11
	BM_MPDec(params,fr,key)

'''
#multiplication chain
for i in range(0, pnum):
	print 'round '+str(i)
	fr=BM_mult_int_Asiacrypt(Cfile1, flst[i], wt_lst, params,32, psize) #11 is the max size of 1234, since 1234<2**11
	BM_MPDec(params,fr,key)

BM_MPDec(params,'intr6',key)
#print 'Multipication finished!'
#BM_MPDec(params,fr_lst[params.ell-2],key) # the result is in fr_lst[params.ell-2]

#BM_add(file1, file2, file3)
#nz=np.dot(DB(key.pk[1:10,:], params.q), key.v.T) %params.q
#nz=[ Noise(z, params) for z in nz ]
#print nz
#print key.v

m1=1
m2=0

C1=PubEnc(params,m1,key)
C2=PubEnc(params,m2,key)

C =Mul(params,C1,C2)

print Dec(params,C1,key)
print Dec(params,C2,key)
print Dec(params,C,key)
'''