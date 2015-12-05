'''
CSE 4344 Computer Networks
Project 3B Packet Sniffer
Team Members: Will Minor, Khanh Ngo, James Staud, Jonathan Kue 

Notes about running this program: 
Use Python 2.7.x with Tkinter and matplotlib libraries installed
Run on a linux OS. This program was mostly tested in Ubuntu, but it should work on most or all linux systems.
***This program does not work on Windows*** 
'''

import Tkinter
import tkMessageBox
import socket, sys
import threading 
import time
import matplotlib.pyplot as plt

from struct import *
global flag
global packetCountList, timeList, packetCount, startTime  #new global variables to plot graph
packetCount = 0
packetCountList = []
timeList = []
flag = True 
 
#Create socket, show error if socket creation fails
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

def go():
	global flag, packetCount,packetCountList, timeList 

	if flag:
		packet = s.recvfrom(65565)

		##########################################################
		endTime = time.time() - startTime
		timeList.append(endTime)
		packetCount += 1
		packetCountList.append(packetCount)

		print startTime		
		print timeList
		print packetCountList
		###########################################################
		#packet string from tuple
		packet = packet[0]
		 
		#parse ethernet header
		e_length = 14
		 
		e_header = packet[:e_length]
		eth = unpack('!6s6sH' , e_header)
		e_protocol = socket.ntohs(eth[2])
		print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(e_protocol)
		textBox.insert(Tkinter.END, 'Destination MAC: ' + eth_addr(packet[0:6])+'\n'+'Source MAC: '+eth_addr(packet[6:12])+'\n'+'Ethernet Protocol: '+ str(e_protocol)+'\n')
		
		#Parse IP packets
		if e_protocol == 8 :
			#Parse IP header, first 20 characters of packet
			ip_header = packet[e_length:20+e_length]
			#unpack returns string in specified format
			iph = unpack('!BBHHHBBH4s4s' , ip_header)
			#separate pieces into variables for readability
			temp_version = iph[0]
			version = temp_version >> 4
			ihl = temp_version & 0xF
			iph_length = ihl * 4
			ttl = iph[5]
			protocol = iph[6]
			source_addr = socket.inet_ntoa(iph[8]);
			destination_addr = socket.inet_ntoa(iph[9]);
			proto = ''
			if protocol == 6:
				proto = 'TCP'
			elif protocol == 17:
				proto = 'UDP'
			elif protocol == 1: 
				proto = 'ICMP'
		
			print 'Version : ' + str(version) + ' IP Header Length: ' + str(ihl) + ' TTL: ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(source_addr) + ' Destination Address : ' + str(destination_addr)
			textBox.insert(Tkinter.END, 'Version: ' + str(version) + '\nIP Header Length: ' + str(ihl) + '\nTTL: ' + str(ttl) + '\nProtocol: ' + str(protocol)+ ' '+proto+ '\nSource Address: ' + str(source_addr) + '\nDestination Address: ' + str(destination_addr)+ '\n')
			#UDP 
			if protocol == 17 :
				udp_index = iph_length + e_length
				udp_header = packet[udp_index:udp_index+8]
		
				#unpack, unsign short ints
				udph = unpack('!HHHH' , udp_header)
				source_port = udph[0]
				destination_port = udph[1]
				length = udph[2]
				checksum = udph[3]
				 
				print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(destination_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
				textBox.insert(Tkinter.END, 'Source Port: ' + str(source_port) + '\nDest Port: ' + str(destination_port) + '\nLength: ' + str(length) + '\nChecksum: ' + str(checksum)+'\n')
				header_size = e_length + iph_length + 8
				data_size = len(packet) - header_size
				 
				#get data from the packet, print to console/terminal, send to GUI text box
				data = packet[header_size:]
				print 'Data : ' + data
				textBox.insert(Tkinter.END, 'Data: '+data+'\n')
			#TCP 
			elif protocol == 6 :
				t = iph_length + e_length
				tcp_header = packet[t:t+20]
		
				#unpack, H: unsign short, L: unsign long, B: unsign char 
				tcph = unpack('!HHLLBBHHH' , tcp_header) 
				source_port = tcph[0]
				destination_port = tcph[1]
				sequence = tcph[2]
				acknowledgement = tcph[3]
				doff_reserved = tcph[4]
				tcph_length = doff_reserved >> 4
				 
				print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(destination_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
				textBox.insert(Tkinter.END,'Source Port: '+str(source_port)+'\n'+'Destination Port: '+str(destination_port)+'\n'+'Sequence Number: '+str(sequence)+'\n'+'Acknowledgement: '+str(acknowledgement)+'\n'+'TCP Header Length: '+str(tcph_length)+'\n') 
				header_size = e_length + iph_length + tcph_length * 4
				data_size = len(packet) - header_size
				 
				#get data from the packet, print to console/terminal, send to GUI text box
				data = packet[header_size:]
				print 'Data : ' + data
				textBox.insert(Tkinter.END, 'Data: '+data+'\n')
			#ICMP 
			elif protocol == 1 :
				u = iph_length + e_length
				icmph_length = 4
				icmp_header = packet[u:u+4]
		
				#unpack, unsign char, unsign char, unsign short
				icmph = unpack('!BBH' , icmp_header)
				icmp_type = icmph[0]
				code = icmph[1]
				checksum = icmph[2]
				 
				print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
				textBox.insert(Tkinter.END,'Type: ' + str(icmp_type) + '\nCode : ' + str(code) + '\nChecksum : ' + str(checksum)+'\n')
				header_size = e_length + iph_length + icmph_length
				data_size = len(packet) - header_size
				 
				#get data from the packet, print to console/terminal, send to GUI text box
				data = packet[header_size:]
				print 'Data : ' + data
				textBox.insert(Tkinter.END, 'Data: '+data+'\n')
			
			#other protocols
			else :
				print 'Protocol other than TCP/UDP/ICMP'
				textBox.insert(Tkinter.END, 'Protocol other than TCP/UDP/ICMP\n')
			textBox.insert(Tkinter.END,'\n------------------------------------------------------------------------------\n')
	else:
		return
	#tk.after(ms,func), gives a window of time for flag value to be reevaluated. Waits specified milliseconds then calls specified function
	tk.after(1500,go)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
	
#Button fuctions
def restart():
	global flag
	global textBox
	flag = True
	startListener()
	
def startListener():
	global flag, startTime
	flag = True	
	print "*********************START*************************"
	startTime = time.time()
	textBox.delete('1.0', Tkinter.END)
	go()

def pauseListener():
	global flag
	print "*********************PAUSE*************************"
	flag = False
	textBox.insert(Tkinter.END,"Paused\n")

def exit():
	print "Exiting"
	tk.destroy()
	sys.exit()

def clear():
	print "Clearing Textbox"
	global textBox, timeList, packetCountList, packetCount
	timeList = []
	packetCountList = []
	packetCount = 0
	textBox.delete('1.0', Tkinter.END)

def graphPlot():
	plt.plot(packetCountList, timeList) #param: two list with values of (time, packet display count)
	plt.xlabel("Packets")
	plt.ylabel("Seconds")
	plt.title("Number of Packets Displayed Over Time")
	plt.show()

#GUI code
tk = Tkinter.Tk()
tk.title("Packet Sniffer")
app = Tkinter.Frame(tk)
app.grid()

textBox = Tkinter.Text(app)
textBox.grid(columnspan = 9, rowspan = 5)
scrollBar = Tkinter.Scrollbar(app, orient = "vertical", command=textBox.yview)
textBox.configure(yscrollcommand=scrollBar.set)

pauseButton = Tkinter.Button(app, text ="Stop", command = pauseListener)
startButton = Tkinter.Button(app, text ="Start", command = restart)
exitButton = Tkinter.Button(app, text = "Exit", command = exit)
clearButton = Tkinter.Button(app, text = "Clear", command = clear)
graphButton = Tkinter.Button(app, text = "Graph", command = graphPlot)

startButton.grid(row = 6, column = 3, sticky= Tkinter.W)
pauseButton.grid(row = 6, column = 4, sticky= Tkinter.W)
exitButton.grid(row = 6, column = 5, sticky= Tkinter.W)
clearButton.grid(row = 6, column = 7, sticky = Tkinter.W)
graphButton.grid(row = 6, column = 6, sticky = Tkinter.W)

scrollBar.configure(command = textBox.yview)
scrollBar.grid(column = 9, row = 6,rowspan=6, columnspan = 10, sticky = Tkinter.N+Tkinter.S+Tkinter.W)



tk.mainloop()
