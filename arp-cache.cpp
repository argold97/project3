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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  m_mutex.lock();
  std::list<PendingPacket> icmpReplies;
  for(std::list<std::shared_ptr<ArpRequest>>::iterator itr = m_arpRequests.begin(); itr != m_arpRequests.end();)
  {
	  ArpRequest* req = itr->get();
	  if(req->nTimesSent >= MAX_SENT_TIME)
	  {
		  for(std::list<PendingPacket>::iterator pend = req->packets.begin(); pend != req->packets.end(); pend++)
			icmpReplies.push_back(*pend);
		  m_mutex.unlock();
		  removeRequest(*(itr++));
		  m_mutex.lock();
		  continue;
	  }
	  req->nTimesSent++;
	  m_router.send_arp_request(req->ip, req->iface);
	  itr++;
  }
  time_t curr_time;
  time(&curr_time);
  for(std::list<std::shared_ptr<ArpEntry>>::iterator itr = m_cacheEntries.begin(); itr != m_cacheEntries.end();)
  {
	  if(itr->get()->timeAdded + SR_ARPCACHE_TO < curr_time)
	  {
		  std::cerr << "Deleted ARP entry " << ipToString(itr->get()->ip) << " " << macToString(itr->get()->mac) << std::endl;
		  m_cacheEntries.erase(itr++);
	  }
	  else
		  itr++;
  }
  m_mutex.unlock();
  
  for(std::list<PendingPacket>::iterator itr = icmpReplies.begin(); itr != icmpReplies.end(); itr++)
  {
	ip_hdr ip_h;
	memcpy((void*)&ip_h, (const void*)itr->packet.data(), sizeof(ip_h));
	Buffer payload = array_to_buffer((uint8_t*)itr->packet.data() + sizeof(ip_h), itr->packet.size() - sizeof(ip_h));
	const Interface* iface = m_router.findIfaceByName(itr->inIface);
	if(iface == nullptr)
	{
		std::cerr << "Error: Missing iface " << itr->inIface << std::endl;
		continue;
	}
	m_router.send_icmp_unreachable(ip_h, payload, iface->ip);
  }
}

void
ArpCache::addArpEntry(const Buffer& mac, uint32_t ip)
{
	std::shared_ptr<ArpRequest> req_s = insertArpEntry(mac, ip);
	if(req_s != nullptr)
	{
		ArpRequest* req = req_s.get();
		for(std::list<PendingPacket>::iterator itr = req->packets.begin(); itr != req->packets.end(); itr++)
		{
			const Interface* iface = m_router.findIfaceByName(itr->iface);
			if(iface != nullptr)
			{
				m_router.send_eth_frame(mac, iface->addr, itr->ethertype, itr->iface, itr->packet);
			}else {
				std::cerr << "Missing iface " << itr->iface << std::endl;
			}
		}
	}
	removeRequest(req_s);
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface, const std::string& inIface, uint16_t ethertype)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip, iface));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface, inIface, ethertype});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  //entry->timeAdded = steady_clock::now();
  time(&entry->timeAdded);
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      //std::lock_guard<std::mutex> lock(m_mutex);

      /*auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }*/

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  //auto now = steady_clock::now();
  time_t curr_time;
  time(&curr_time);
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       //<< std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << curr_time - entry->timeAdded << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
