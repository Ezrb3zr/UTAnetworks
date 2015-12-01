'''
Important: Run with administrator cmd.exe
Make sure your python in is your PATH 
Add python to your path by going to Control Panel -> System and Security -> System -> Advanced System Settings -> Environment Variables
Edit PATH, add location of python folder to the end of Variable value. Make sure to use a ; to separate from the previous file path 
Ex. ......;C:\Python27
'''
#This program prints out the hex of one packet. Use this to test if the socket protocols work on your windows OS. 
#Also, use this to test speed, sometimes even this simple program takes a while to print out the packet details. 
import socket, sys
HOST = socket.gethostbyname(socket.gethostname())
s = socket.socket( socket.AF_INET , socket.SOCK_RAW , socket.IPPROTO_IP)
s.bind((HOST, 0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
print("Test 0")
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
print("Test 1")
print s.recvfrom(2048)
print("Test 2")
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) #turns off promiscuous mode (stop receiving packets)
s.close()
