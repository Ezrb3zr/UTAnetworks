import Tkinter
import tkMessageBox
import socket, sys
import threading #added for gui



from struct import *
global flag
flag = True 


#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

def go():
	global flag
	if flag:
		packet = s.recvfrom(65565)
		#packet string from tuple
		packet = packet[0]
		 
		#parse ethernet header
		eth_length = 14
		 
		eth_header = packet[:eth_length]
		eth = unpack('!6s6sH' , eth_header)
		eth_protocol = socket.ntohs(eth[2])
		print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
		textBox.insert(Tkinter.END, 'Destination MAC: ' + eth_addr(packet[0:6])+'\n'+'Source MAC: '+eth_addr(packet[6:12])+'\n'+'Ethernet Protocol: '+ str(eth_protocol)+'\n')
		#Parse IP packets, IP Protocol number = 8
		if eth_protocol == 8 :
			#Parse IP header
			#take first 20 characters for the ip header
			ip_header = packet[eth_length:20+eth_length]
			 
			#now unpack them :)
			iph = unpack('!BBHHHBBH4s4s' , ip_header)
		
			version_ihl = iph[0]
			version = version_ihl >> 4
			ihl = version_ihl & 0xF
		
			iph_length = ihl * 4
		
			ttl = iph[5]
			protocol = iph[6]
			s_addr = socket.inet_ntoa(iph[8]);
			d_addr = socket.inet_ntoa(iph[9]);
			proto = ''
			if protocol == 6:
				proto = 'TCP'
			elif protocol == 17:
				proto = 'UDP'
			elif protocol == 1: 
				proto = 'ICMP'
		
			print 'Version : ' + str(version) + ' IP Header Length: ' + str(ihl) + ' TTL: ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
			textBox.insert(Tkinter.END, 'Version: ' + str(version) + '\nIP Header Length: ' + str(ihl) + '\nTTL: ' + str(ttl) + '\nProtocol: ' + str(protocol)+ ' '+proto+ '\nSource Address: ' + str(s_addr) + '\nDestination Address: ' + str(d_addr)+ '\n')
			#TCP protocol
			if protocol == 6 :
				t = iph_length + eth_length
				tcp_header = packet[t:t+20]
		
				#now unpack them :)
				tcph = unpack('!HHLLBBHHH' , tcp_header)
				 
				source_port = tcph[0]
				dest_port = tcph[1]
				sequence = tcph[2]
				acknowledgement = tcph[3]
				doff_reserved = tcph[4]
				tcph_length = doff_reserved >> 4
				 
				print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
				textBox.insert(Tkinter.END,'Source Port: '+str(source_port)+'\n'+'Destination Port: '+str(dest_port)+'\n'+'Sequence Number: '+str(sequence)+'\n'+'Acknowledgement: '+str(acknowledgement)+'\n'+'TCP Header Length: '+str(tcph_length)+'\n') 
				h_size = eth_length + iph_length + tcph_length * 4
				data_size = len(packet) - h_size
				 
				#get data from the packet
				data = packet[h_size:]
				 
				print 'Data : ' + data
				textBox.insert(Tkinter.END, 'Data: '+data+'\n')
			#ICMP Packets
			elif protocol == 1 :
				u = iph_length + eth_length
				icmph_length = 4
				icmp_header = packet[u:u+4]
		
				#now unpack them
				icmph = unpack('!BBH' , icmp_header)
				 
				icmp_type = icmph[0]
				code = icmph[1]
				checksum = icmph[2]
				 
				print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
				textBox.insert(Tkinter.END,'Type: ' + str(icmp_type) + '\nCode : ' + str(code) + '\nChecksum : ' + str(checksum)+'\n')
				h_size = eth_length + iph_length + icmph_length
				data_size = len(packet) - h_size
				 
				#get data from the packet
				data = packet[h_size:]
				 
				print 'Data : ' + data
				textBox.insert(Tkinter.END, 'Data: '+data+'\n')
			#UDP packets
			elif protocol == 17 :
				u = iph_length + eth_length
				udph_length = 8
				udp_header = packet[u:u+8]
		
				#now unpack them :)
				udph = unpack('!HHHH' , udp_header)
				 
				source_port = udph[0]
				dest_port = udph[1]
				length = udph[2]
				checksum = udph[3]
				 
				print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
				textBox.insert(Tkinter.END, 'Source Port: ' + str(source_port) + '\nDest Port: ' + str(dest_port) + '\nLength: ' + str(length) + '\nChecksum: ' + str(checksum)+'\n')
				h_size = eth_length + iph_length + udph_length
				data_size = len(packet) - h_size
				 
				#get data from the packet
				data = packet[h_size:]
				 
				print 'Data : ' + data
				textBox.insert(Tkinter.END, 'Data: '+data+'\n')
			#some other IP packet like IGMP
			else :
				print 'Protocol other than TCP/UDP/ICMP'
				textBox.insert(Tkinter.END, 'Protocol other than TCP/UDP/ICMP\n')
			textBox.insert(Tkinter.END,'\n--------------------------------------------\n')
	else:
		return
	tk.after(1500,go)
	#sys.exit()

def restart():
	global flag
	global textBox
	flag = True
	textBox.delete('1.0', Tkinter.END)
	startListener()
	
def startListener():
	global flag
	flag = True	
	print "*********************START*************************"
	go()
	# if flag:
	# 	print "start"
	# tk.after(1000, startListener)

def pauseListener():

	global flag
	print "*********************PAUSE*************************"
	flag = False
def exit():
	print "Exiting"
	tk.destroy()
	sys.exit()
def clear():
	print "Clearing Textbox"
	global textBox
	textBox.delete('1.0', Tkinter.END)


tk = Tkinter.Tk()
tk.title("Packet Sniffer")
#tk.geometry("200x200")

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

startButton.grid(row = 6, column = 3, sticky= Tkinter.W)
pauseButton.grid(row = 6, column = 4, sticky= Tkinter.W)
exitButton.grid(row = 6, column = 5, sticky= Tkinter.W)
clearButton.grid(row = 6, column = 7, sticky = Tkinter.W)

# text = Tkinter.Text(app)
# text.insert(Tkinter.INSERT, "testing1111111111111111111111111")
# text.insert(Tkinter.END, "ending")
# text.pack()
scrollBar.grid(column = 9, rowspan = 5)
tk.mainloop()
