import thread
import time
from threading import Thread
import sys, os,threading, time, traceback, getopt
import paramiko
import terminal
import select
import sys
import Queue

import SocketServer

term = terminal.TerminalController()
paramiko.util.log_to_file('demo.log')

print "\n*************************************"
print "*"+term.RED + "SSH Forwarder Scanner Ver. 0.1"+term.NORMAL+"     *"
print "*Edge-Security Research             *"
print "*Coded by                           *"
print "*Christian Martorella               *"
print "*cmartorella@edge-security.com      *"
print "*Xavier Mendez aka Javi		    *"
print "*xmendez@edge-security.com          *"
print "*************************************\n"

def usage():
    print "Usage: scanssh.py options \n"
    print "       -h: target host"
    print "       -u: username"
    print "       -p: password"
    print "       -l: targets lists to scan"
    print "       -t: threads"
    print "       --remote-host: host to scan"
    print "       --remote-ports: port list to scan"
    print "       --default-ports: scan default ports"
    print "       --all-ports: scan all 65535 ports"
    print "       --keep-tunnels: Forward all open ports"
    print "\nExamples:\n"
    print "\tscanssh.py -h 192.168.1.55 -u root -p passowrd -t list.txt"
    print "\tscanssh.py -h 192.168.1.55 -u root -p password --remote-host 127.0.0.1 --remote-ports 80,443"
    print "\tscanssh.py -h 192.168.1.55 -u root -p password --remote-host 127.0.0.1 --default-ports\n"
    sys.exit()

class ForwardServer(SocketServer.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    
class Handler(SocketServer.BaseRequestHandler):
    def handle(self):
        try:
            chan = self.transport.open_channel('direct-tcpip',
                                                   (self.chain_host, self.chain_port),
                                                   self.request.getpeername())
        except Exception, e:
            verbose('Incoming request to %s:%d failed: %s' % (self.chain_host,
                                                              self.chain_port,
                                                              repr(e)))
            return
        if chan is None:
            verbose('Incoming request to %s:%d was rejected by the SSH server.' %
                    (self.chain_host, self.chain_port))
            return

        verbose('Connected!  Tunnel open %r -> %r -> %r' % (self.request.getpeername(),
                                                            chan.getpeername(), (self.chain_host, self.chain_port)))
        while True:
            r, w, x = select.select([self.request, chan], [], [])
            if self.request in r:
                data = self.request.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                self.request.send(data)
        chan.close()
        self.request.close()
        verbose('Tunnel closed from %r' % (self.request.getpeername(),))

class tunnel_thread(Thread):
    def __init__(self,local_port, remote_host, remote_port, transport):
	Thread.__init__(self)
	self.local_port = local_port
	self.remote_host = remote_host
	self.remote_port = remote_port
	self.transport = transport

    def run(self):
	class SubHander (Handler):
	    chain_host = self.remote_host
	    chain_port = self.remote_port
	    transport = self.transport
	ForwardServer(('', self.local_port), SubHander).serve_forever()

class scan_thread(Thread):
	def __init__( self,remotehost,remoteport,starthost,transport,ctrlq, open_ports ):
	    Thread.__init__(self)
	    self.remotehost = remotehost
	    self.remoteport = int(remoteport)
	    self.starthost = starthost
	    self.transport = transport
	    self.ctrlq = ctrlq
	    self.open_ports = open_ports

	def run(self):
	    chan=None
	    try:
		chan = self.transport.open_channel('direct-tcpip', (self.remotehost, self.remoteport), (self.starthost,22))  
		print "[+] OPEN PORT:" + self.remotehost + " : " + str(self.remoteport)
		self.open_ports.put((self.remotehost, self.remoteport))
	    except Exception, e:
	        #print "Closed port " + self.remotehost + " : " + str(self.remoteport)
	        pass
	    finally:
		if chan: chan.close()
		self.ctrlq.get()
		self.ctrlq.task_done()

def verbose(s):
    print s
		
class scanssh:
    def __init__(self, names, starthost, username, password, th):
	self.ctrlq = Queue.Queue(th)
	self.username = username
	self.password = password
	self.names = names
	self.starthost = starthost
	self.transport = None
	self.open_ports = Queue.Queue()
	self.client = None

	self.connect()

    def connect(self):
	# Connect SSH Host
	self.client = paramiko.SSHClient()
	self.client.load_system_host_keys()
	self.client.set_missing_host_key_policy(paramiko.WarningPolicy())

	print "Connecting to %s....." % self.starthost
	try:
	    self.client.connect(self.starthost, port=22, username=self.username, password=self.password)
	    self.transport = self.client.get_transport()
	except Exception, e:
	    print e

    def port_scan(self):
	if not self.transport: 
	    return

	# Scan through SSH Host
	for i in self.names:
	    ip, port = i.split(":")
	    #print "Trying port %s." % port
	    self.ctrlq.put(1)
	    thread = scan_thread(ip, port, self.starthost, self.transport, self.ctrlq, self.open_ports)
	    thread.start()
	self.ctrlq.join()

    def keep_tunnel(self):
	if not self.transport: 
	    return

	# Forward all identified channels
	while not self.open_ports.empty():
	    remotehost, remoteport = self.open_ports.get()

	    print "Opening %s:%d..." % (remotehost, remoteport)

	    thread = tunnel_thread(remoteport, remotehost, remoteport, self.transport)
	    thread.start()

if __name__ == "__main__":
    try:
	hostname = None
	username = None
	targets = None
	remoteh = None
	remotep = None
	keep = False

	th = 12
	if len(sys.argv) < 3:
		usage()
	try :
	    opts, args = getopt.getopt(sys.argv[1:],"vh:u:d:t:p:l:", ["remote-host=", "remote-ports=","default-ports","all-ports","keep-tunnels"])
	except getopt.GetoptError:
	    usage()

	for opt,arg in opts:
	    if opt == '-u':
		    username = arg
	    elif opt == '-h':
		    hostname =arg
	    elif opt == '-p':
		    password = arg
	    elif opt == "-t":
		    th = int(arg)
	    elif opt == "--remote-host":
		    remoteh = arg
	    elif opt == "--all-ports":
		    remotep = ",".join([str(x) for x in range(1,65535)])
	    elif opt == "--default-ports":
		    #remotep = ",".join([str(x) for x in range(1,1024)])
		    remotep = "21,22,23,3389,3306,1521,1433,389,139,445,80,443,8080"
	    elif opt == "--remote-ports":
		    remotep = arg
	    elif opt == "--keep-tunnels":
		    keep = True
	    elif opt == "-l":
		    targets= arg

	targetlist = None
	if targets:
	    try:
		    f = open(targets, "r")
		    targetlist = f.readlines()
	    except:
		    print "Can't open target file\n"
		    sys.exit()
	elif remoteh and remotep:
	    targetlist = map(lambda x:[x+":" + port for port in remotep.split(",")],remoteh.split(","))
	    targetlist = targetlist[0]
	else:
	    usage()
	    sys.exit(2)

	print term.RED + "HOST: " +term.NORMAL +  hostname + term.RED 
	print "Username: " +term.NORMAL +  username +term.RED 
	print "========================================================="
	starttime = time.clock()
	sssh = scanssh(targetlist, hostname, username, password, th)
	sssh.port_scan()
	stoptime = time.clock()
	print "\nTimes -- > Init: "+ str(starttime) + " End: "+str(stoptime)
	print "\n"

	if keep:
	    print "Forwarding open ports..."
	    sssh.keep_tunnel()
	    while(1): pass
    except KeyboardInterrupt:
	    print "Attack suspended by user...\n"
	    sys.exit()
