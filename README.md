UCLA CS118 Project 3 (Simple Router) COVFEFE    
====================================

Nicholas Turk - 004579860 
Uday Alla - 404428077 
Alex Gold - 804561696 

-All of us worked on everything. 

Succesfully implemented the following functions:
	
	- void SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface);
		1. Extract iface 
		2. Construct Ethernet header from the input packet 
		3. Find destination iface by destination MAC address 
		4. Make payload(Packet data + ethernet header)
		5. Check packet type
			6. if ARP type
				- handle ARP Packet
					-extract arp header from arp packet 
					-find op_code to check if  it is an ARP request/reply 
					-if it is a request, send reply
					-if it is a reply, add it as an arp entry to the arp cache
		    7. if IP type 
		    	-  handle IP packet
		    		-extract ip header from ip packet
		    		-calculate checksum and check if valid
		    		-create ip payload with packet data and ip header
		    		-find destination iface by ip from ip header
		    		- 1.if destination iface not found, forward ip packet to passed-in iface
		    			-check ttl
		    				- if 1 send ICMP timeout 
		    				- else decrement ttl, recompute checksum and send IP packet 
		    		-2. else if ip_protocol is icmp, handle icmp packet
		    				- extract ICMP header from ICMP packet (woosh)
		    				- compute checksum 
		    			 	- check ICMP type:
		    			 		-if ECHO send ICMP_ECHO_REPLY
		    			 		- else drop packet


	- void ArpCache::periodicCheckArpRequestsAndCacheEntries(); 
		1. iterate through ARP cache
		2. for each ARP request:
			-check number of times sent 
			-if sent 5 or more times drop/remove request from cache
			-else send ARP request 
				- extract destination interface
				-create the ARP header and fill the header with infromation extracted from the interface and default  values
				-then pack the arp header into a packet
				- send packet
		3. iterate through the ARP cache again and if the entry exceeed 30s remove it 

	- RoutingTableEntry RoutingTable::lookup(uint32_t ip) const;
		1. iterate through the routing table
		2. Use longestPrefixMatching algorithm to find the next forwarding ip 

Problem we ran into:

	- Big endian / little endian confusion for computing checksums

	- Byte order 

	- figuring out traceroute was hard (still in the process of learning)

Libraries used:

	C++11 standard library

	netdb

	socket

	arpa/inet

Online tutorials:

	Man pages on https://linux.die.net
	
	C++ reference guide on http://www.cplusplus.com 