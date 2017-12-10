#encoding:utf-8
#author：lshc
#data:2017.7.12
import ftplib
import sys
import argparse
import queue
from threading import *


class ftp_weaklogin(Thread):  #定义ftp_weaklogin类
	def __init__(self,queue):
		Thread.__init__(self)
		self._queue=queue

	def run(self):
		while not self._queue.empty():
			targethost=self._queue.get()
			try:
				self.scan(targethost)
			except:
				pass

	def scan(self,hostname): #定义扫描函数
		try:
			a=True
			fn=open('passwd.txt','r')
			for line in fn.readlines():	#遍历密码表
				try:
					name=line.strip('\n').split(':')[0]
					passwd=line.strip('\n').split(':')[1]
					ftp=ftplib.FTP(hostname,timeout=5)
					ftp.login(str(name),str(passwd))
					print('[+]%s:%s login succeed[%s]'%(name,passwd,hostname))
					f1=open('scan_reslt.txt','a+')
					f1.write('[+]%s:%s login succeed[%s]'%(name,passwd,hostname)+'\n')
					f1.close()
					ftp.quit()
					a=False
					break
				except:
					pass
			fn.close()
			if(a):
				print('[-]%s login failed'%(hostname))
		except:
			print('failed')
			sys.exit(0)


def main():
	parser=argparse.ArgumentParser(usage='[option] -H <targetHost> -w <scanway-option-A\B\C> -r <threads>')
	parser.add_argument('-H',dest='targetHost')
	parser.add_argument('-w',dest='scanway')
	parser.add_argument('-r',dest='thread1')
	given_args=parser.parse_args()
	tgthost=given_args.targetHost
	scanway1=given_args.scanway
	thread2=given_args.thread1
	if((tgthost==None)|(scanway1==None)):
		print(parser.usage)
		sys.exit(0)

	threads=[]
	if(thread2==None):
		thread_max=50
	else:
		thread_max=int(thread2)
	tgthostqueue=queue.Queue()
	
	try:
		if(scanway1=='A' or scanway1=='a' ):#A段扫描
			for i in range(1,256):
				for j in range(1,256):
					for k in range(1,256):
						tgthostqueue.put(tgthost.split('.')[0]+'.'+str(i)+'.'+str(j)+'.'+str(k))

		elif(scanway1=='B' or scanway1=='b'):#B段扫描
			for i in range(1,256):
				for j in range(1,256):
					tgthostqueue.put(tgthost.split('.')[0]+'.'+tgthost.split('.')[1]+'.'+str(i)+'.'+str(j))
		elif(scanway1=='C' or scanway1=='c'):#C段扫描
			for i in range(1,256):
				tgthostqueue.put(tgthost.split('.')[0]+'.'+tgthost.split('.')[1]+'.'+tgthost.split('.')[2]+'.'+str(i))
		else:
			sys.exit(0)	

		for i in range(thread_max):
			threads.append(ftp_weaklogin(tgthostqueue))

		for i in threads:
			i.start()
		for i in threads:
			i.join()
	except:
		print('程序异常')
		sys.exit(0)


if(__name__=='__main__'):
	f1=open('scan_reslt.txt','w')
	f1.close()
	main()

