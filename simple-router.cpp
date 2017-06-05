/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <cstring>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  
  print_hdrs(packet);
  std::cerr << std::endl;
  
  if(packet.size() < sizeof(ethernet_hdr))
	  return;
  
  ethernet_hdr ethernet_h;
  std::memcpy(&ethernet_h, (const void*)packet.data(), sizeof(ethernet_h));
  
  Buffer dest = array_to_buffer((uint8_t*)&ethernet_h.ether_dhost, ETHER_ADDR_LEN);
  
  if(dest != bcast_mac)
  {
	const Interface* dest_iface = findIfaceByMac(dest);
	if(dest_iface == nullptr || dest_iface != findIfaceByName(inIface))
	{
		std::cerr << "Dropped packet: Bad destination" << std::endl;
		return;
	}
  }
  
  const Buffer payload = array_to_buffer((uint8_t*)packet.data() + sizeof(ethernet_hdr), packet.size() - sizeof(ethernet_hdr));
  
  switch(ntohs(ethernet_h.ether_type))
  {
	  case ethertype_arp:
		handlePacket_arp(payload, inIface);
		break;
	  case ethertype_ip:
		handlePacket_ip(payload);
		break;
	  default:
		std::cerr << "Dropped packet: Bad type" << std::endl;
		return;
  }

}

void
SimpleRouter::handlePacket_arp(const Buffer& packet, const std::string& inIface)
{
	arp_hdr arp_h;
	memcpy((void*)&arp_h, (const void*)packet.data(), sizeof(arp_hdr));
	
	if(ntohs(arp_h.arp_op) == arp_op_request)
	{
		if(findIfaceByIp(arp_h.arp_tip) == findIfaceByName(inIface))
		{
			send_arp_reply(arp_h, inIface);
		}else {
			std::cerr << "Dropped ARP request: Bad target IP" << std::endl;
		}
		return;
	}
}

void
SimpleRouter::send_arp_reply(const arp_hdr& arp_r, const std::string& inIface)
{
	const Interface* iface = findIfaceByName(inIface);
	if(iface == nullptr)
	{
		std::cerr << "Error: Missing iface" << std::endl;
		return;
	}
	
	ethernet_hdr ethernet_h;
	memcpy((void*)&ethernet_h.ether_dhost, (const void*)arp_r.arp_sha, ETHER_ADDR_LEN);
	memcpy((void*)&ethernet_h.ether_shost, (const void*)iface->addr.data(), ETHER_ADDR_LEN);
	ethernet_h.ether_type = htons(ethertype_arp);
	
	arp_hdr arp_h;
	arp_h.arp_hrd = htons(arp_hrd_ethernet);
	arp_h.arp_pro = htons(ethertype_ip);
	arp_h.arp_hln = ETHER_ADDR_LEN;
	arp_h.arp_pln = IP_ADDR_LEN;
	arp_h.arp_op = htons(arp_op_reply);
	arp_h.arp_sip = iface->ip;
	arp_h.arp_tip = arp_r.arp_sip;
	memcpy((void*)&arp_h.arp_sha, (const void*)iface->addr.data(), ETHER_ADDR_LEN);
	memcpy((void*)&arp_h.arp_tha, (const void*)arp_r.arp_sha, ETHER_ADDR_LEN);
	
	Buffer packet;
	pack_hdr(packet, (uint8_t*)&ethernet_h, sizeof(ethernet_h));
	pack_hdr(packet, (uint8_t*)&arp_h, sizeof(arp_h));
	
	sendPacket(packet, inIface);
}

void
SimpleRouter::send_arp_request(uint32_t tip_addr, const std::string& outIface)
{
	const Interface* iface = findIfaceByName(outIface);
	if(iface == nullptr)
	{
		std::cerr << "Error: Missing iface" << std::endl;
		return;
	}
	
	ethernet_hdr ethernet_h;
	memcpy((void*)&ethernet_h.ether_dhost, (const void*)bcast_mac.data(), ETHER_ADDR_LEN);
	memcpy((void*)&ethernet_h.ether_shost, (const void*)iface->addr.data(), ETHER_ADDR_LEN);
	
	arp_hdr arp_h;
	arp_h.arp_hrd = htons(arp_hrd_ethernet);
	arp_h.arp_pro = htons(ethertype_ip);
	arp_h.arp_hln = ETHER_ADDR_LEN;
	arp_h.arp_pln = IP_ADDR_LEN;
	arp_h.arp_op = htons(arp_op_request);
	arp_h.arp_sip = iface->ip;
	arp_h.arp_tip = tip_addr;
	memcpy((void*)&arp_h.arp_sha, (const void*)iface->addr.data(), ETHER_ADDR_LEN);
	memcpy((void*)&arp_h.arp_tha, (const void*)bcast_mac.data(), ETHER_ADDR_LEN);
	
	Buffer packet;
	pack_hdr(packet, (uint8_t*)&ethernet_h, sizeof(ethernet_h));
	pack_hdr(packet, (uint8_t*)&arp_h, sizeof(arp_h));
	
	sendPacket(packet, outIface);
}

void 
SimpleRouter::handlePacket_ip(const Buffer& packet)
{
	if(packet.size() < sizeof(ip_hdr))
		return;
	
	ip_hdr ip_h;
	std::memcpy((void*)&ip_h, (const void*)packet.data(), sizeof(ip_h));
	
	uint16_t chk = cksum((const void*)&ip_h, sizeof(ip_h));
	if(chk != 0xFFFF)
	{
		std::cerr << "Dropped IP packet: Bad cksum" << std::endl;
		return;
	}
	
	if(packet.size() < ntohs(ip_h.ip_len))
	{
		std::cerr << "Dropped IP packet: Invalid length" << std::endl;
		return;
	}
	
	Buffer payload = array_to_buffer((uint8_t*)packet.data() + ip_h.ip_hl * 4, ntohs(ip_h.ip_len) - ip_h.ip_hl * 4);		
	
	const Interface* dest_iface = findIfaceByIp(ip_h.ip_dst);
	
	if(dest_iface == nullptr)
		forward_ip_packet(ip_h, payload);
	else if(ip_h.ip_p == ip_protocol_icmp)
		handlePacket_icmp(ip_h, payload);
	else
		std::cerr << "Dropped IP packet: Addressed to router but no ICMP message" << std::endl;
}

void
SimpleRouter::forward_ip_packet(const ip_hdr& ip_h, const Buffer& payload)
{
	RoutingTableEntry next_hop = getRoutingTable().lookup(ip_h.ip_dst);
	
	std::cerr << "Next hop: " << ipToString(next_hop.gw) << " " << next_hop.ifName << std::endl;
}

void
SimpleRouter::handlePacket_icmp(const ip_hdr& ip_h, const Buffer& packet)
{
	if(packet.size() < sizeof(icmp_hdr))
		return;
	
	icmp_hdr icmp_h;
	memcpy((void*)&icmp_h, (const void*)packet.data(), sizeof(icmp_h));
	
	uint16_t chk = cksum((const void*)packet.data(), packet.size());
	if(chk != 0xFFFF)
	{
		std::cerr << "Dropped ICMP message: Bad cksum" << std::endl;
		return;
	}
	
	if(icmp_h.icmp_type == icmp_echo)
	{
		send_icmp_echo_reply(ip_h.ip_dst, ip_h.ip_src, array_to_buffer((uint8_t*)packet.data() + sizeof(icmp_h), packet.size() - sizeof(icmp_h)));
	}else {
		std::cerr << "Dropped ICMP message: Unknown type" << std::endl;
	}
}

void
SimpleRouter::send_icmp_echo_reply(uint32_t sip_addr, uint32_t tip_addr, const Buffer& data)
{
	ip_hdr ip_h;
	ip_h.ip_hl = sizeof(ip_h) / 4;
	ip_h.ip_v = ip_v4;
	ip_h.ip_tos = 0;
	ip_h.ip_len = sizeof(ip_h) + data.size();
	ip_h.ip_id = 0;
	ip_h.ip_off = 0;
	ip_h.ip_ttl = ICMP_ECHO_TTL;
	ip_h.ip_p = ip_protocol_icmp;
	ip_h.ip_sum = 0;
	ip_h.ip_src = sip_addr;
	ip_h.ip_dst = tip_addr;
	ip_h.ip_sum = cksum((const void*)&ip_h, sizeof(ip_h));
	
	icmp_hdr icmp_h;
	icmp_h.icmp_type = icmp_echo_reply;
	icmp_h.icmp_code = 0;
	icmp_h.icmp_sum = 0;
	
	Buffer payload;
	pack_hdr(payload, (uint8_t*)&icmp_h, sizeof(icmp_h));
	pack_hdr(payload, (uint8_t*)data.data(), data.size());
	
	uint16_t chk = cksum((const void*)payload.data(), payload.size());
	memcpy((void*)(payload.data() + sizeof(icmp_h.icmp_type) + sizeof(icmp_h.icmp_code)), (const void*)&chk, sizeof(chk));
	
	forward_ip_packet(ip_h, payload);
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
