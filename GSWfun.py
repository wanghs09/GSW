#!/usr/bin/python
import math
import random
import sys
import numpy as np
import collections
from scipy.stats import bernoulli,poisson,norm,expon
import tables as tb
import pickle
import glob,os,resource,time

'''
class poisson_gen(rv_discrete):
	"Poisson distribution"
	def _pmf(self, k, mu):
		return math.exp(-mu) * mu**k / math.factorial(k)

poisson = poisson_gen(name="poisson")
'''

q=2**31 #primes(2**31)
n=2**10
CHUNK=2**10 #the number of rows in one chunk for matrix n*n

PARAMS=collections.namedtuple('PARAMS',['m','n','ell','N','G', 'alpha','q', 'var'])
KEY   =collections.namedtuple('KEY',['sbar','s'])

random.seed(2016)

#boolean function
def HE_bin_fun():
	BM_SecEnc(params, 1, key, Cfile1)
	BM_SecEnc(params, 0, key, Cfile2)
	BM_SecEnc(params, 1, key, Cfile3)
	#BM_add(Cfile1, Cfile2, Cfile, params)
	#BM_mult2(Cfile1, Cfile2, Cfile, params)
	BM_mult3(Cfile1, Cfile2, Cfile, params,2)
	BM_mult3(Cfile3, Cfile, Cfile_end, params,2) #multiply fresh ciphertext from left side
	BM_mult3(Cfile3, Cfile_end, Cfile, params,2)
	BM_Dec(params,Cfile1,key)
	BM_Dec(params,Cfile2,key)
	#BM_Dec(params,Cfile1,key)

	BM_Dec(params,Cfile_end,key)
	BM_Dec(params,Cfile,key)

#homomorphic integer, straighforward way
def HE_int_fun():
	width= math.ceil(math.log(12*78*78,2))
	print "plaintext width=%d" %width

	BM_SecEnc(params, 12, key, Cfile1)
	BM_SecEnc(params, 78, key, Cfile2)
	BM_SecEnc(params, 1, key, Cfile3)
	#BM_add(Cfile1, Cfile2, Cfile, params)
	BM_mult3(Cfile1, Cfile2, Cfile, params,32)
	BM_mult3(Cfile2, Cfile, Cfile_end, params,32) #mult an integer
	BM_MPDec(params,Cfile,key)
	BM_MPDec(params,Cfile_end,key)

	BM_mult3(Cfile3, Cfile_end, Cfile, params,32) #mult a 1-bit
	BM_MPDec(params,Cfile,key)

#homomorphic integer, Asiacrypt way
def HE_int_fun_Asiacrypt():
	#clean
	map(os.remove, glob.glob('cipher*'))
	map(os.remove, glob.glob('int*'))

	#parameters
	pnum=6
	psize=7
	flst_pfx='int_'

	flst=[]
	for i in range(0, pnum): 
		flst.append([])
		for j in range(0, psize): 
			flst[i].append(flst_pfx+str(i)+'_'+str(j))

	#initial ciphertext
	BM_SecEnc(params, 1, key, Cfile1)

	#encrypt all integers to a ciphertext vector
	#generate random numbers
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

	#Integer multplication chain
	fr='intr6' #file for intemediate results
	for i in range(1, pnum):
		print 'round '+str(i)
		fr=BM_mult_int_Asiacrypt(fr, flst[i], wt_lst, params,32, psize) #11 is the max size of 1234, since 1234<2**11
		BM_MPDec(params,fr,key)

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
	fparams = open('params.file', 'rb')
	params = pickle.load(fparams)
	key = pickle.load(fparams)
	fparams.close()
	yield params
	yield key

def test_table():
	ndim = 60000
	h5file = tb.openFile('test.h5', mode='w', title="Test Array")
	root = h5file.root
	#Float64Atom
	x = h5file.createCArray(root,'x',tb.UInt32Atom(),shape=(ndim,ndim))
	x[:100,:100] = np.random.random_integers(0, 100,size=(100,100)) # Now put in some data
	#print x[1:3,1:10]
	h5file.close()

#big matrix generation
def BM_gen(file,params):
	h5file = tb.openFile(file, mode='w', title="Test Array")
	root = h5file.root
	x = h5file.createCArray(root,'x',tb.UInt32Atom(),shape=(params.n,params.n))
	x[:CHUNK,:] = np.random.random_integers(0, params.q,size=(CHUNK,params.n)) # Now put in some data
	#print h5file
	h5file.close()

#big matrix G generation
def BM_G(file,n,ell,N):
	h5file = tb.openFile(file, mode='w', title="Test Array")
	root = h5file.root
	x = h5file.createCArray(root,'x',tb.UInt32Atom(),shape=(n,N))
	
	g = [ 2**z for z in np.arange(ell) ]
	for i in range(0, n):
		x[i,ell*i:ell*(i+1)] = g
	
	#print x[0,0:ell]
	h5file.close()

#big matrix addition
#file=file1+file2
def BM_add(file1, file2, file, params):
	h5file1 = tb.open_file(file1)
	h5file2 = tb.open_file(file2)	
	
	h5file = tb.openFile(file, mode='w', title="Test Array")	
	root = h5file.root
	x = h5file.createCArray(root,'x',tb.UInt32Atom(),shape=(params.n,params.N))
	
	for i in range(0, params.n//CHUNK):
		x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), :]
		x2 = h5file2.root.x[CHUNK*i:CHUNK*(i+1), :]

		x[CHUNK*i:CHUNK*(i+1), :]=x1+x2 %params.q

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
	x3 = h5file2.createCArray(root3,'x',tb.UInt32Atom(),shape=(params.N,params.N))
	
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
	x3 = h5file2.createCArray(root3,'x',tb.UInt32Atom(),shape=(params.n,params.N))
	
	for i in range(0, params.n//CHUNK):
		for j in range(0, params.N//CHUNK):
			#print 'start timer:'
			#start=time.time()
			x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), :]
			x2 = h5file2.root.x[:,CHUNK*j:CHUNK*(j+1)]
			#print time.time()-start
			#start=time.time()

			x2inv=Ginv(x2, params)
			#print time.time()-start
			#start=time.time()

			y=np.dot(x1,x2inv) %params.q
			#print time.time()-start
			#start=time.time()

			x3[CHUNK*i:CHUNK*(i+1), CHUNK*j:CHUNK*(j+1)]=y # store
			#print time.time()-start
			#start=time.time()

		#print i
	h5file1.close()
	h5file2.close()
	h5file3.close()

#only cal one column: params.N, because only this one is necessary for decryption
#but we cal two columns to avoid np array error
#colcal is the number of columns to cal
#big matrix mult with G^{-1}
#file3=file1*file2
def BM_mult3(file1, file2, file3, params,colcal):
	h5file1 = tb.open_file(file1)
	h5file2 = tb.open_file(file2)	
	
	h5file3 = tb.openFile(file3, mode='w', title="Test Array")	
	root3 = h5file3.root
	x3 = h5file2.createCArray(root3,'x',tb.UInt32Atom(),shape=(params.n,params.N))
	
	for i in range(0, params.n//CHUNK):
		j=params.N-2

		#start=time.time()
		x1 = h5file1.root.x[CHUNK*i:CHUNK*(i+1), :]
		x2 = h5file2.root.x[:,(j-colcal):(j+1)] ##but we cal two columns to avoid np array error
		#print time.time()-start
		#start=time.time()

		x2G=Ginv(x2, params)
		#print time.time()-start
		#start=time.time()

		y=np.dot(x1,x2G) %params.q
		#print time.time()-start
		#start=time.time()

		x3[CHUNK*i:CHUNK*(i+1), (j-colcal):(j+1)]=y # store

		#print time.time()-start
		#print i
		#print x2G
	h5file1.close()
	h5file2.close()
	h5file3.close()

#Asiacrypt16 method
#integer encryption
#fr_lst[params.ell-2] is the result ciphertext
#the filename defines the prefix of the ciphertext file names
def BM_SecEnc_int_Asiacrypt(integer, flst, key, params, psize):
	B_lst=dec_to_bin(integer, params.ell)
	for i in range(0, psize):
		BM_SecEnc(params, B_lst[i], key, flst[i])

#Asiacrypt16 method
#integer multiplication
#fr_lst[params.ell-2] is the result ciphertext
#psize: plaintext size, so that only psize weights will be used
def BM_mult_int_Asiacrypt(file, file_lst, wt_lst, params,colcal, psize):
	map(os.remove, glob.glob('tmp*'))

	ftmp_lst=[]
	ftmp2_lst=[]
	fr_lst=[]
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
		BM_mult2(file_lst[i], file, ftmp_lst[i], params)
		BM_mult3(ftmp_lst[i], wt_lst[i], ftmp2_lst[i], params,colcal)

		#C1[i]* (Ginv(C2)* Ginv(W[i]) )
		#BM_mult3(file, wt_lst[i], ftmp_lst[i], params,colcal)
		#BM_mult3(file_lst[i], ftmp_lst[i], ftmp2_lst[i], params,colcal)

		#initial accumulator with ftmp_lst[0]
		if i==0:
			fr_lst[0]=ftmp2_lst[0]

		#sum
		if i>0:
			BM_add(ftmp2_lst[i], fr_lst[i-1], fr_lst[i], params)
	
	return fr_lst[psize-1]
	
#########################################
def Setup(L,LM=80):
	#q=2**31-1 #primes(2**31)
	#n=2**10

	#q=2**20-1 #primes(2**31)
	#n=2**4 #small n to test functionality

	ell=int(math.floor(math.log(q,2))+1)
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
	x = Cfile.createCArray(root,'x',tb.UInt32Atom(),shape=(params.n,params.N))
	
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
	x = Cfile.createCArray(root,'x',tb.UInt32Atom(),shape=(params.n,params.N))
	
	Gfile = tb.openFile(params.G)
	for i in range(0, params.n):
		x1 = Gfile.root.x[i, :]
		x[i,:]  = m*x1 %params.q
	Gfile.close()
	Cfile.close()

def BM_Dec(params,fileC, key):
	Cfile = tb.openFile(fileC)
	cvec=Cfile.root.x[:, params.N-2] #pemultimate column
	Cfile.close()

	tmp=np.dot(key.s,cvec) %params.q
	print tmp
	tmp=min(tmp, abs(2**(params.ell-1)-tmp)) #round to less than q/2
	noise=min(abs(tmp), abs(2**(params.ell-2)-tmp))
	m=0
	if abs(2**(params.ell-2)-tmp)<abs(tmp):
		m=1

	print 'noise=%d, m=%d' %(noise, m)
	return m

#Multi-precision decoding for integers
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
	mat2=mat
	for i in range(0, len):
		x[i:mat.shape[0]*len:len, :]=mat2%2 #every mat.shape[0] element, LSB
		mat2=mat2//2 #right shift
	return x

#[LSB LSB+1 ... MSB]
def dec_to_bin(x,len):
	x=int(x)
	str=bin(x)[2:].zfill(len)
	x=[ bool(int(x)) for x in list(str) ] #here make it bool
	x=np.asarray(x)
	#print x.shape

	return np.flipud(x)

def Gau(n_sample, var):
  x=norm.rvs(scale=var,size=n_sample)
  x = [ int(z) for z in x ]
  x=np.asarray(x).reshape(-1,1)
  return x

def Noise(val, params):
  x=min(val, params.q-val)
  return x

#test the err of R*e
def tst(params):
  R=np.random.random_integers(0,1,(params.N,params.m))
  e=Gau(params.m, params.var)
  print max(np.dot(R,e))  