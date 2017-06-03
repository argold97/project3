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
  
  ethernet_hdr ethernet_h;
  std::memcpy(&ethernet_h, (const void*)packet.data(), sizeof(ethernet_hdr));
  
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
	memcpy((void*)&arp_h.arp_sha, (const void*)iface->addr.data(), ETHER_ADDR_LEN);
	memcpy((void*)&arp_h.arp_tha, (const void*)arp_r.arp_sha, ETHER_ADDR_LEN);
	arp_h.arp_sip = arp_r.arp_tip;
	arp_h.arp_tip = arp_r.arp_sip;
	
	Buffer packet;
	for(size_t i = 0; i < sizeof(ethernet_h); i++)
	{
		packet.push_back(((uint8_t*)&ethernet_h)[i]);
	}
	for(size_t i = 0; i < sizeof(arp_h); i++)
	{
		packet.push_back(((uint8_t*)&arp_h)[i]);
	}
	
	sendPacket(packet, inIface);
}

void 
SimpleRouter::handlePacket_ip(const Buffer& packet)
{
	
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
