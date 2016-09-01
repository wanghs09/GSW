#!/usr/bin/python
import math, random, sys
import numpy as np
import collections
from scipy.stats import bernoulli,poisson,norm,expon
#from scipy.stats import norm
#import scipy
import tables as tb
import pickle
import glob,os,resource,time

random.seed(2016)

#debug
DEBUG=0

#GSW global params
lm=80 #security level
L=10  #level of circuits

q=2**31-2**6-1 #primes(2**31)
#q=2**31-2**5-1 #primes(2**31)
ell=int(math.floor(math.log(q,2))+1)
n=2**10
CHUNK=2**10 #the number of rows in one chunk for matrix n*n


Cfile1='cipher1' #initial ciphertext, encrypt(1) for the beginning of a multiplication chain

PARAMS=collections.namedtuple('PARAMS',['m','n','ell','N','G', 'alpha','q', 'var'])
KEY   =collections.namedtuple('KEY',['sbar','s'])

params, key = "", ""

#weights file list
wt_lst=[]
flst=[]

#integer ciphertexts file list
pnum=7 #plaintext multiply chain number

#Interger list
#int_lst=[377001, 376915, 375415, 511411, 432336, 520148] #[np.random.random_integers(1,2**psize) for i in range(pnum)]  
int_lst=[120, 117, 65, 97, 45, 113, 77]

#use naf or not, if use psize should have one more bit
#plaintext size <7-bit
flag_NAF, flag_partial_add, psize=1, 1, 9

flst_pfx, ftmp, ftmp2, ftmp3='int_', 'ctmp',  'ctmp2', 'ctmp3'


def note():
	print "-----------------Function list------------------------"
	print "clean: clean cached params and regenerate"
	print "00: boolean HE operation test"
	print "00: integer HE operation test, the straightforward way"
	print "10: prepare for Asiacrypt16 multiplication chain"
	print "11: integer HE operation test, the Asiacrypt16 way"
	print "20: HE bit extraction"
	print "------------------------------------------------------"

#General q enc/dec test
def Gq_test_fun():
	params,key=params_read()

	# m1=1
	# BM_SecEnc(params, m1, key, ftmp)
	# nd(params,ftmp,key, m1)

	# BM_mult3(ftmp, wt_lst[10], ftmp2, params,32)
	# nd(params,ftmp2,key, m1*2**10)

	# fr=Cfile1 #file for intemediate results
	#nd(params,fr,key, 1)
	
	BM_SecEnc(params,1, key, ftmp)
	BM_SecEnc(params,1, key, ftmp2)
	# BM_PlainEnc(params, 2**1, key, wt_lst[1])
	BM_mult3(ftmp,  ftmp2, ftmp3, params, 32)


	print nd(params,ftmp,key, 1)
	print nd(params,ftmp3,key, 1)
	#test a*2**k mod q
	# m1=-1
	# BM_SecEnc(params,m1, key, ftmp)
	# nd(params,ftmp,key, m1%params.q)
	# nd(params,wt_lst[10],key, 2**10)

	# BM_mult3(ftmp,  wt_lst[14], ftmp2, params, 35)
	# print str(m1*2**14 %params.q)
	# nd(params,ftmp2,key, m1*2**14 %params.q)

	# BM_mult2(Cfile1, flst[0][0], ftmp2, params)
	# BM_mult3(Cfile1,  flst[0][0], ftmp2, params, 32)#flst[0][0]
	# BM_mult3(Cfile1,  ftmp2, ftmp, params, 32)#flst[0][0]
	# nd(params,ftmp2,key, 0)
	# nd(params,ftmp,key, 0)

	# fr=BM_mult_int_Asiacrypt(fr, flst[0], wt_lst, params,32, psize) #11 is the max size of 1234, since 1234<2**11
	# nd(params,fr,key, int_lst[0])
	# fr=BM_mult_int_Asiacrypt(fr, flst[1], wt_lst, params,32, psize) #11 is the max size of 1234, since 1234<2**11
	# nd(params,fr,key, int_lst[0]*int_lst[1])
	#MPDec(params,flst[1][1],key)
	

#boolean function
def HE_bin_fun():
	params,key=params_read()

	BM_SecEnc(params, 1, key, flst[1])
	BM_SecEnc(params, 0, key, flst[2])
	BM_SecEnc(params, 1, key, flst[3])
	#BM_add(Cfile1, Cfile2, Cfile, params)
	#BM_mult2(Cfile1, Cfile2, Cfile, params)
	BM_mult3(flst[1], flst[2], flst[4], params,32)
	BM_mult3(flst[3], flst[4], flst[5], params,32) #mult an integer
	BM_MPDec(params,flst[5],key)
 
#homomorphic integer, straighforward way
def HE_int_fun():
	params,key=params_read()

	m1=12
	m2=78
	m3=79
	width= math.ceil(math.log(m1*m2*m3,2))
	print "plaintext width=%d" %width

	BM_SecEnc(params, m1, key, flst[1][1])
	BM_SecEnc(params, m2, key, flst[2][1])
	BM_SecEnc(params, m3, key, flst[3][1])
	#BM_add(Cfile1, Cfile2, Cfile, params)
	BM_mult3(flst[1][1], flst[2][1], flst[4][1], params,32)
	nd(params,flst[4][1],key, m1*m2)

	BM_mult3(flst[3][1], flst[4][1], flst[5][1], params,32) #mult an integer
	nd(params,flst[5][1],key, m1*m2*m3)

	#MPDec(params,flst[5][1],key)

#homomorphic bit extraction
#dec_to_bin
#http://www.binaryhexconverter.com/decimal-to-binary-converter
def HE_ext_bit():
	params,key=params_read()

	randint=78
	len=int(math.ceil(math.log(randint,2)))
	print "Integer(bin):"
	print dec_to_bin(randint, len)
	print flst[0]
	BM_SecEnc(params, randint, key, flst[0][0])

	Cfile = tb.openFile(flst[0][0])
	x=Cfile.root.x[:, (params.N-len-1):(params.N-1)] #pemultimate column
	#x = h5file.createCArray(root,'x',tb.Int64Atom(),shape=(params.n,params.N))
	#x = x[:, (params.N-len-1):(params.N-1)] #N*len matrix
	Cfile.close()

	#for i in range(0, len-1):
	#	x[:,(len-2-i)] = (2*x[:,(len-2-i)]-x[:,(len-1-i)])//2

	for i in range(0, len-1):
		x[:,i] = (2*x[:,i]-x[:,i+1])//2

	#print x

	#dec every bit
	for i in range(len-1, -1, -1):
		vec_Dec(x[:,i], key)
	

#homomorphic integer, Asiacrypt way
#Integer multplication chain
def HE_int_fun_Asiacrypt(prepared=0):
	params,key=params_read()
	#[37, 15, 45, 86, 127, 98]
	#noise simulation, Jun 13
	'''
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
	'''
	if prepared==0: #unprepared
		map(os.remove, glob.glob('cipher*'))
		map(os.remove, glob.glob('w*'))
		map(os.remove, glob.glob('int*'))

		#initial ciphertext=enc(1)
		BM_SecEnc(params, 1, key, Cfile1)

		#encrypt weights
		for i in range(1, params.ell-1): #less than 2**(ell-1)
			BM_PlainEnc(params, 2**i, key, wt_lst[i])			
		
		#encrypt integers
		for i in range(0, 7): 
		#for i in range(0, pnum):
			BM_SecEnc_int_Asiacrypt(int_lst[i], flst[i], key, params, psize) #filename = 'int_integer name_weight'

		print 'Encryption finished!'
	else:		
		#test noise of weights
		# for i in range(0, pnum):
			# nd(params,wt_lst[i],key, 2**i)

		fr=Cfile1 #file for intemediate results
		plt=1
		i=0

		fr=BM_mult_int_Asiacrypt(0, fr, flst[0], wt_lst, params,32, psize, 1) #initial ones
		map(os.remove, glob.glob('int_'+str(i)+'*')) #save disk space

		print '-----------round '+str(0)
		plt=plt*int_lst[0] %params.q
		print 'plaintext: '+str(plt)
		print 'noise='+ str(max(nd(params,fr,key, plt)))

		# for i in range(0, pnum):
		for i in range(1, 7):
			fr=BM_mult_int_Asiacrypt(1, fr, flst[i], wt_lst, params,32, psize, plt) #11 is the max size of 1234, since 1234<2**11
			map(os.remove, glob.glob('int_'+str(i)+'*'))
			map(os.remove, glob.glob('*tmp*'))

			#plaintext
			print '-----------round '+str(i)
			plt=plt*int_lst[i] %params.q
			print 'plaintext: '+str(plt)
			print 'noise='+ str(max(nd(params,fr,key, plt)))


			#MPDec(params,fr,key)  #display the noise after every mult

#generate params and write into a file
def params_write(L):
	#lm=80
	#L=10
	params=Setup(L)
	key=KeyGen(params)
	fparams = open('params.file', mode='wb')
	pickle.dump(params,fparams)
	pickle.dump(key,fparams)

	print params
	fparams.close()

#read pre-calculated params from a file
def params_read():
	global params, key
	fparams = open('params.file', 'rb')
	params = pickle.load(fparams)
	key = pickle.load(fparams)
	fparams.close()
	print params

	yield params
	yield key

def test_table():
	ndim = 60000
	h5file = tb.openFile('test.h5', mode='w', title="Test Array")
	root = h5file.root
	#Float64Atom
	x = h5file.createCArray(root,'x',tb.Int64Atom(),shape=(ndim,ndim))
	x[:100,:100] = np.random.random_integers(0, 100,size=(100,100)) # Now put in some data
	#print x[1:3,1:10]
	h5file.close()

#big matrix generation
def BM_gen(file,params):
	h5file = tb.openFile(file, mode='w', title="Test Array")
	root = h5file.root
	x = h5file.createCArray(root,'x',tb.Int64Atom(),shape=(params.n,params.n))
	x[:CHUNK,:] = np.random.random_integers(0, params.q,size=(CHUNK,params.n)) # Now put in some data
	h5file.close()

#big matrix G generation
def BM_G(file,n,ell,N):
	h5file = tb.openFile(file, mode='w', title="Test Array")
	root = h5file.root
	x = h5file.createCArray(root,'x',tb.Int64Atom(),shape=(n,N))
	
	g = [ 2**z for z in np.arange(ell) ]
	for i in range(0, n):
		x[i,ell*i:ell*(i+1)] = g
	
	#print 'G:'+str(x[0,0:ell])
	h5file.close()

#big matrix addition
#file=file1+file2
def BM_add(file1, file2, file, params, flag_partial_add):
	h5file1 = tb.open_file(file1)
	h5file2 = tb.open_file(file2)	
	
	h5file = tb.openFile(file, mode='w', title="Test Array")	
	root = h5file.root
	x = h5file.createCArray(root,'x',tb.Int64Atom(),shape=(params.n,params.N))
	
	for i in range(0, params.n//CHUNK):
		if flag_partial_add==0:
			x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), :]
			x2 = h5file2.root.x[CHUNK*i:CHUNK*(i+1), :]
			x[CHUNK*i:CHUNK*(i+1), :]=x1+x2 %params.q
		else:
			x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), (params.N-params.ell): params.N]
			x2 = h5file2.root.x[CHUNK*i:CHUNK*(i+1), (params.N-params.ell): params.N]
			x[CHUNK*i:CHUNK*(i+1), (params.N-params.ell): params.N]=x1+x2 %params.q

	h5file1.close()
	h5file2.close()
	h5file.close()

#big matrix mult
#file3=file1*file2
def BM_mult(file1, file2, file3, params):
	h5file1 = tb.open_file(file1)
	h5file2 = tb.open_file(file2)	
	
	h5file3 = tb.openFile(file3, mode='w', title="Test Array")	
	root3 = h5file3.root
	x3 = h5file2.createCArray(root3,'x',tb.Int64Atom(),shape=(params.N,params.N))
	
	for i in range(0, params.N//CHUNK):
		for j in range(0, params.N//CHUNK):
			x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), :]
			x2 = h5file2.root.x[:,CHUNK*j:CHUNK*(j+1)]

			x3[CHUNK*i:CHUNK*(i+1), CHUNK*j:CHUNK*(j+1)]=np.dot(x1,x2) %params.q

	h5file1.close()
	h5file2.close()
	h5file3.close()

#big matrix mult with G^{-1}
#file3=file1*file2
def BM_mult2(file1, file2, file3, params):
	h5file1 = tb.open_file(file1)
	h5file2 = tb.open_file(file2)	
	
	h5file3 = tb.openFile(file3, mode='w', title="Test Array")	
	root3 = h5file3.root
	x3 = h5file2.createCArray(root3,'x',tb.Int64Atom(),shape=(params.n,params.N))
	
	for i in range(0, params.n//CHUNK):
		for j in range(0, params.N//CHUNK):
			x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), :]
			x2 = h5file2.root.x[:,CHUNK*j:CHUNK*(j+1)]

			x2inv=Ginv(x2, params)

			y=np.dot(x1,x2inv) %params.q

			x3[CHUNK*i:CHUNK*(i+1), CHUNK*j:CHUNK*(j+1)]=y # store
	h5file1.close()
	h5file2.close()
	h5file3.close()

#only cal one column: params.N, because only this one is necessary for decryption
#but we cal two columns to avoid np array error
#colcal is the number of columns to cal
#big matrix mult with G^{-1}
#file3=file1*file2
def BM_mult3(file1, file2, file3, params,colcal): #ignore colcal
	h5file1 = tb.open_file(file1)
	h5file2 = tb.open_file(file2)	
	
	h5file3 = tb.openFile(file3, mode='w', title="Test Array")	
	root3 = h5file3.root
	x3 = h5file2.createCArray(root3,'x',tb.Int64Atom(),shape=(params.n,params.N))
	
	for i in range(0, params.n//CHUNK):
		j=params.N

		x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), :]
		x2 = h5file2.root.x[:,(j-params.ell):j] ##but we cal two columns to avoid np array error
		x2G= Ginv(x2, params)
		x3[CHUNK*i:CHUNK*(i+1), (j-params.ell):j]=np.dot(x1,x2G) %params.q
	h5file1.close()
	h5file2.close()
	h5file3.close()

#Asiacrypt16 method
#integer encryption
#fr_lst[params.ell-2] is the result ciphertext
#the filename defines the prefix of the ciphertext file names
#flag_NAF: use naf or not
def BM_SecEnc_int_Asiacrypt(integer, flst, key, params, psize):
	#encoding
	if flag_NAF==1:
		B_lst=naf(integer, params.ell)
	else:
		B_lst=dec_to_bin(integer, params.ell)

	# print B_lst

	#encryption
	for i in range(0, psize):
		BM_SecEnc(params, B_lst[i], key, flst[i])

#Asiacrypt16 method
#integer multiplication
#fr_lst[params.ell-2] is the result ciphertext
#psize: plaintext size, so that only psize weights will be used
#mode: 0 for inital ciphertext, no need to use mult2
#plt: the plaintext number encrypted in file
def BM_mult_int_Asiacrypt(mode, file, file_lst, wt_lst, params,colcal, psize, plt):
	map(os.remove, glob.glob('tmp*'))

	ftmp_lst, ftmp2_lst, fr_lst=[], [], []
	for i in range(0, params.ell-1): #less than 2**(ell-1)
		ftmp_lst.append('tmp'+str(i))
		ftmp2_lst.append('tmp-2'+str(i))
		fr_lst.append('intr'+str(i))
	
	#weight*u1*u2[i]
	for i in range(0, psize):
	#for i in range(0, params.ell-1):
		#BM_mult3(file1, file2, file3, params,colcal) #for continuous mult
		#print 'weight:'+str(i)

		#memory usage
		#print resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1000

		#(C1[i]*Ginv(C2))* Ginv(W[i]) 
		if mode==0:
			BM_mult3(file_lst[i], wt_lst[i], ftmp2_lst[i], params,params.ell)
		else:
			# BM_mult2(file_lst[i], file, ftmp_lst[i], params)
			BM_mult3(file_lst[i], file, ftmp_lst[i], params, params.ell)
			BM_mult3(ftmp_lst[i], wt_lst[i], ftmp2_lst[i], params,params.ell)
		
		#test every step noise
		if 1:
			print 'bit '+str(i)+':'
			noise1=nd(params,ftmp2_lst[i],key, (2**i * plt)%params.q )
			noise2=nd(params,ftmp2_lst[i],key, (-2**i * plt)%params.q)
			noise3=nd(params,ftmp2_lst[i],key, 0)

			noise=min(max(noise1), max(noise2), max(noise3))
			if noise==max(noise1):
				print noise1
			elif noise==max(noise2):
				print noise2
			elif noise==max(noise3):
				print noise3
		#C1[i]* (Ginv(C2)* Ginv(W[i]) )
		#BM_mult3(file, wt_lst[i], ftmp_lst[i], params,colcal)
		#BM_mult3(file_lst[i], ftmp_lst[i], ftmp2_lst[i], params,colcal)

		#initial accumulator with ftmp_lst[0]
		if i==0:
			fr_lst[0]=ftmp2_lst[0]
		else:#sum
			BM_add(ftmp2_lst[i], fr_lst[i-1], fr_lst[i], params, 1) #only need to add part of the ciphertext
	
	return fr_lst[psize-1]
	
#########################################
def ini():
	#weights file list
	global wt_lst
	for i in range(0, ell-1): #less than 2**(ell-1)
		wt_lst.append("w"+str(i))

	global flst
	for i in range(0, pnum): 
		flst.append([])
		for j in range(0, psize): 
			flst[i].append(flst_pfx+str(i)+'_'+str(j))

def Setup(L,LM=80):
	#q=2**31-1 #primes(2**31)
	#n=2**10

	#q=2**20-1 #primes(2**31)
	#n=2**4 #small n to test functionality

	
	m=2*n*ell #O(nlogq)
	N=int(n*ell)
	alpha=10
	var=10
  	G=BM_G('params.G',n,ell,N)

	params=PARAMS(m,n,ell,N,'params.G',alpha,q, var)
	return params

# GSW variant from Peikert's paper
def KeyGen(params):
	sbar=Gau(params.n-1, params.var) %params.q # (n-1)*1 matrix
	#print sbar.shape
	s=np.append(sbar,[1])
	key=KEY(sbar,s)
	return key

#file = SecEnc(m), stored in a Cfile, ciphertext file
def BM_SecEnc(params,m, key, fileC):
	Cbar=np.random.random_integers(0,params.q,(params.n-1,params.N))
	e=Gau(params.N, params.var) %params.q
	b=(np.dot(np.transpose(key.sbar),Cbar)) %params.q
	b=(np.transpose(e)-b) %params.q #1*N array

	#initial C=(Cbar b^t)
	C=np.concatenate((Cbar,b),axis=0)

	#create ciphertext file
	Cfile = tb.openFile(fileC, mode='w', title="Test Array")
	root = Cfile.root
	x = Cfile.createCArray(root,'x',tb.Int64Atom(),shape=(params.n,params.N))

	Gfile = tb.openFile(params.G)
	for i in range(0, params.n):
		x1 = Gfile.root.x[i, :]
		x[i,:]  = C[i,:]+m*x1 %params.q
	Gfile.close()
	Cfile.close()

#file = BM_PlainEnc(m), stored in a Cfile, ciphertext file, 
#encrypt a plaintext without noise
def BM_PlainEnc(params,m, key, fileC):
	#create ciphertext file
	Cfile = tb.openFile(fileC, mode='w', title="Test Array")
	root = Cfile.root
	x = Cfile.createCArray(root,'x',tb.Int64Atom(),shape=(params.n,params.N))
	
	Gfile = tb.openFile(params.G)
	for i in range(0, params.n):
		x1 = Gfile.root.x[i, :]
		tmp  = (m*x1) %params.q
		x[i,:]=tmp
		# print str(i)+':'+str(x[i,:])
	# print str(x[params.n-1, (params.N-params.ell) : params.N])
	Gfile.close()
	Cfile.close()

def BM_Dec(params,fileC, key):
	Cfile = tb.openFile(fileC)
	cvec=Cfile.root.x[:, params.N-2] #pemultimate column
	Cfile.close()
	vec_Dec(cvec, key)

#decode a vector ciphertext
def vec_Dec(cvec, key):
	tmp=np.dot(key.s,cvec) %params.q
	print tmp
	tmp=min(tmp, abs(2**(params.ell-1)-tmp)) #round to less than q/2
	noise=min(abs(tmp), abs(2**(params.ell-2)-tmp))
	m=0
	if abs(2**(params.ell-2)-tmp)<abs(tmp):
		m=1

	print 'noise=%d, m=%d' %(noise, m)
	return m

#noise detection, given the expected plaintext plt
def nd(params, fileC, key, plt):
	Cfile = tb.openFile(fileC)
	cvec=Cfile.root.x[:, (params.N-params.ell):(params.N)]  #ell-1 columns
	cvec2=np.dot(key.s,cvec) %params.q
	Cfile.close()

	#get ciphertext cvec2 with zero noise
	noise=np.ones(params.ell)
	for i in range(0, params.ell):
		noise[i]=abs(2**i*plt%params.q-cvec2[i])
		noise[i]=min(abs(noise[i]), abs(params.q-noise[i]))  
		if 1:
			print  str(cvec2[i])+':'+ str(2**i*plt%params.q)

	# print 'noise vector:'+str(noise)
	# noise=max(noise)
	# print 'noise:'+str(noise)
	return noise

#Multi-precision decoding for integers
def MPDec(params,fileC, key):
	if params.q==2**(params.ell-1):
		BM_MPDec(params,fileC,key)
	else:
		Gq_MPDec(params,fileC,key)

def BM_MPDec(params,fileC, key):
	Cfile = tb.openFile(fileC)
	
	MAXnoise=0 #need the max noise coefficient
	m=0
	for i in range(0, params.ell-1):
	#for i in range(0, 11):
		cvec=Cfile.root.x[:, params.N-2-i] #pemultimate column
		tmp=np.dot(key.s,cvec) %params.q
		tmp=tmp-m*2**(params.ell-2-i) %params.q 
		#print tmp
		tmp=min(tmp, abs(2**(params.ell-1)-tmp)) #round to less than q/2
		noise=min(abs(tmp), abs(2**(params.ell-2)-tmp))

		if abs(2**(params.ell-2)-tmp)<abs(tmp):
			m=2**i+m

		if noise>MAXnoise:
			MAXnoise=noise
	print 'tmp=%d, noise=%d, m=%d' %(tmp,MAXnoise, m)
	
	Cfile.close()
	return m

#Multi-precision decoding for integers 
#with a general q
def Gq_MPDec(params,fileC, key):
	Cfile = tb.openFile(fileC)
	
	MAXnoise=0 #need the max noise coefficient
	m=0
	for i in range(0, params.ell-2):
	#for i in range(0, 11):
		cvec =Cfile.root.x[:, params.N-1-i] #pemultimate column
		cvec2=Cfile.root.x[:, params.N-2-i] #the second column to get the differential

		tmp=(np.dot(key.s,cvec) -m*2**(params.ell-2-i)) %params.q
		tmp2=(np.dot(key.s,cvec2) -m*2**(params.ell-3-i)) %params.q

		tmp=2*tmp2-tmp  
		if DEBUG:
			print str(i)+':'+bin(tmp)


		#tmp=tmp//2**(params.ell-2)
		#print tmp
		#if (tmp==2) | (tmp==1) :

		if not((tmp<=0) | (abs(tmp)<2**(params.ell-3)) ):
			m=m+2**i


		#tmp=min(tmp, abs(2**(params.ell-1)-tmp))
		#if abs(2**(params.ell-2)-tmp)<abs(tmp):
		#	m=2**i+m
		
		#if tmp>=2**(params.ell-1):
		#	m=2**i+m

		#print m

	m=2*m
	#decode m[0]
	cvec =Cfile.root.x[:, params.N-1] #pemultimate column
	tmp=(np.dot(key.s,cvec) %params.q) - (m*2**(params.ell-1)%params.q) 
	if DEBUG:
		print str(i)+':'+bin(tmp)

	if not((tmp<=0) | (abs(tmp)<2**(params.ell-3)) ):
		m=m+1

	#print 'tmp=%d, noise=%d, m=%d' %(tmp,MAXnoise, m)
	print 'plaintext=%d' %(m)
	
	Cfile.close()
	return m

#### original GSW from Gentry's paper
def KeyGen2(params):
	t=np.random.random_integers(0,params.q-1,(params.n,1))
	B=np.random.random_integers(0,params.q-1,(params.m,params.n))

	#e should be gaussian
	#e=np.random.random_integers(0,params.q-1,(params.m,1))
	e=Gau(params.m, params.var) %params.q
  
	#b=np.multiply(B,t.T)
	b=np.add(np.dot(B,t), e)%params.q
	A=np.concatenate((b,B),axis=1)

	# generate v
	t1=np.negative(t).T
	t1=np.insert(t1,0,1) %params.q #axis 0, value 1

	len=int(math.floor(math.log(params.q,2))+1)
	weight = [ 2**(len-z-1) for z in np.arange(len) ]

	v=np.zeros((1, (params.n+1)*len))
	for i in range(0, params.n+1):
		v[0, i*len: (i+1)*len]=np.multiply(t1[i],weight) %params.q

	key=KEY(t,v,A)
	return key

def PubEnc(params,m, key):
	R=np.random.random_integers(0,1,(params.N,params.m))
	I=np.identity(params.N)
	C=Flatten(np.add(np.multiply(m,I), DB(np.dot(R,key.pk), params.q)), params.q)
	return C

def Mul(params,C1,C2):
	C=Flatten(np.dot(C1,C2),params.q)
	return C

def Add(params,C1,C2):
	C=Flatten(C1+C2,params.q)
	return C

def Dec(params,C, key):
	tmp=np.dot(C[1,:],key.v.T) %params.q
	tmp=min(tmp, abs(params.q-tmp)) #round to less than q/2
	noise=min(tmp, params.q/2-tmp)
	m=0
	if abs(params.q/2-tmp)>abs(tmp):
		m=1

	print 'noise=%d' %noise
	
	return m

def Flatten(mat,q):
	tmp=DBI(mat,q)
	x=DB(tmp,q)
	return x

#decompose matrix B all elements to l-bit binary representations
#decreasing weight
def DB(mat,q):
	len=int(math.floor(math.log(q,2))+1)
	x=np.zeros((mat.shape[0], mat.shape[1]*len))
	for i in range(0, mat.shape[0]):
		for j in range(0, mat.shape[1]):
			x[i,j*len:(j*len+len)]=dec_to_bin(mat[i,j]%q,len)
    
	return x

#compose matrix l-bit binary representation B to mod q matrix
#decreasing weight
def DBI(mat,q):
	len=int(math.floor(math.log(q,2))+1)
	x=np.zeros((mat.shape[0], mat.shape[1]//len))
	weight = [ 2**(len-z-1) for z in np.arange(len) ]

	for i in range(0, x.shape[0]):
		for j in range(0, x.shape[1]):
			x[i,j]=np.dot(mat[i,j*len:(j*len+len)], weight) %q
    
	return x

#Ginv: Z^(n*m) -> Z^(n*ell *m) 
#here we make it DB
#decreasing weight
def Ginv(mat,params):
	len=params.ell
	x=np.zeros((mat.shape[0]*len, mat.shape[1]))

	mat2=mat% params.q
	for i in range(0, len):
		x[i:mat.shape[0]*len:len, :]=mat2%2 #every mat.shape[0] element, LSB
		mat2=mat2//2 #right shift

	# np.set_printoptions(threshold=np.inf)
	# print np.sum(x, axis=0)
	return x

#[LSB LSB+1 ... MSB]
def dec_to_bin(x,len):
	x=int(x)
	str=bin(x)[2:].zfill(len)
	x=[ bool(int(x)) for x in list(str) ] #here make it bool
	x=np.asarray(x)
	#print x.shape

	return np.flipud(x)

#NAF encoder
#no continuous 1
def naf(k,len):
	x=[ 0 for z in range(len) ]

	i=0
	while k>=1:
		if k%2==1:
			x[i]=2- (k%4)
			k=k - x[i]
		else:
			x[i]=0
		k=k//2
		i=i+1

	return x

def Gau(n_sample, var):
  x=norm.rvs(scale=var,size=n_sample)
  x = [ int(z) for z in x ]
  x=np.asarray(x).reshape(-1,1)
  # print 'error:' + str(x)
  return x

def Noise(val, params):
  x=min(val, params.q-val)
  return x

#test the err of R*e
def tst(params):
  R=np.random.random_integers(0,1,(params.N,params.m))
  e=Gau(params.m, params.var)
  print max(np.dot(R,e))  

'''
class poisson_gen(rv_discrete):
	"Poisson distribution"
	def _pmf(self, k, mu):
		return math.exp(-mu) * mu**k / math.factorial(k)

poisson = poisson_gen(name="poisson")
'''  