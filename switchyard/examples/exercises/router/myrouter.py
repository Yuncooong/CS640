#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
	self.my_interfaces = self.net.interfaces()
        self.my_ipaddr = [intf.ipaddr for intf in self.my_interfaces]
	self.my_ipmac_pair = {}
    def 

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
		log_debug("Got a packet: {}".format(str(pkt)))
		#to obtain the ARP header
		arp = packet.get_header(Arp)
		#get the ARP header
		if arp:
			#if is an Arp request
			if arp.operation == ArpOperation.Request:
				#add ip, mac pair into my map
				my_ipmac_pair[arp.senderprotoaddr] = arp.senderhwaddr
				#if IP address destination is in my router interface
				if arp.targetprotoaddr in self.my_ipaddr:
					#send ARP reply
					senderhwaddr = self.net.interface_by_ipaddr(arp.targetprotoaddr).ethaddr
					targethwaddr = arp.senderhwaddr
					senderprotoaddr = arp.targetprotoaddr
					targetprotoaddr = arp.senderprotoaddr
					self.net.send_packet(dev, create_ip_arp_reply(senderhwaddr, targethwaddr,\ 
										      senderprotoaddr, targetprotoaddr))
			#if is not an ARP request,
			else:




		#task2
		#to obtain the ip header
		ip = packet.get_header(IPv4)
		if ip:
		
	    #if not got packet
	    else:
                	    
		
	



def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
