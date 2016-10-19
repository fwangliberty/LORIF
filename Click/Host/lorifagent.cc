/*
 * ip6ndsolicitor.{cc,hh} -- Neighborhood Solicitation element
 * Peilei Fan
 *
 * Copyright (c) 1999-2001 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "lorifagent.hh"
#include <clicknet/ether.h>
#include <clicknet/himalis.h>
#include <click/etheraddress.hh>
#include <click/ip6address.hh>
#include <click/args.hh>
#include <click/straccum.hh>
#include <click/bitvector.hh>
#include <click/error.hh>
#include <click/glue.hh>

CLICK_DECLS

LorifAgent::LorifAgent()
{
    // input 0: IP6 packets be encapsulated
	// input 1: lorif packets to be decapsulated to regular IP6 packets
    // output 0: lorif packets to network
	// output 1: IP6 packets to host
  for (int i = 0; i < NMAP; i++)
	  _ltable[i] = 0;
}

LorifAgent::~LorifAgent()
{
}

int
LorifAgent::configure(Vector<String> &conf, ErrorHandler *errh)
{
	// first, read the ipv6 address and loclist of the host
	Args(conf, this, errh)
	.read_mp("IP", _my_ip6)
	.read_mp("LocList", _my_loclist)
	.execute();

	// Second, read the locators
	IP6Address ip6, loclist;

	for (int i = 2; i < conf.size(); i++) {
		ip6 = IP6Address(cp_shift_spacevec(conf[i]));
		loclist = IP6Address(cp_shift_spacevec(conf[i]));
		//click_chatter("%{element}: inserting locator %x for locator %x", this, ip6.data()[0], loclist.data()[0]);

		if(insert(ip6, loclist) == -1){
			break;
		}
	}
	return  0;
}

int
LorifAgent::insert(IP6Address dstid, IP6Address locator)
{
	// first find the entry from the locator table
	int bucket = (dstid.data()[0] + dstid.data()[15]) % NMAP;
	LocEntry *ley = _ltable[bucket];
	while (ley && ley->_dstid != dstid)
	    ley = ley->next;
	//click_chatter("find the entry");

	if(ley) {
		// find the entry, check if ipv6 is the same address
		//click_chatter("find ley");
		if(ley->_dstid != dstid) {
			ley->_dstid =dstid;
		}else return 0;
	}else{
		// create a new entry and add it to the first element of the chain
	    LocEntry *newley = new LocEntry;
	    newley->_dstid = dstid;
	    newley->_loclist = IP6Address("::0");
	    unsigned char *xi = locator.data();
	    //click_chatter("%{element}: adding the locator %x", this, xi[0]);
	    for(int i = 0; i< 16; i++)
	    	newley->_loclist.data()[i] = xi[i];
	    newley->next = _ltable[bucket];
	    _ltable[bucket] = newley;
	}
	//click_chatter("finishing inserting");
	return 0;
}

int
LorifAgent::remove_route(IP6Address dhid)
{
	int bucket = (dhid.data()[0] + dhid.data()[15]) % NMAP;

	LocEntry *ley = _ltable[bucket];
	LocEntry *pre;

	// check if the entry from _ltable has the ID
	if(!ley) return 0;

	if(ley && ley->_dstid == dhid){
		pre = ley->next;
		_ltable[bucket] = pre;
		return 0;
	}else {
		while (ley->_dstid != dhid) {
			pre = ley;
			ley = ley->next;
		}

		if(ley){
			pre->next = ley;
		}else return 0;
	}
	return 0;
}

int
LorifAgent::loclist_encap(Packet *p)
{
	IP6Address ipa = DST_IP6_ANNO(p);
	int bucket = (ipa.data()[0] + ipa.data()[15]) % NMAP;
	//click_chatter("ipa[0] is %x and ipa[15] is %x", ipa.data()[0], ipa.data()[15]);
	//click_chatter("outgoing bucket is %d", bucket);
	LocEntry *ae = _ltable[bucket];
	if(ae) { //click_chatter("ae is 1");
	} else {
	 //click_chatter("ae is 0");
	 return 0;
        }

	while (ae) {
	   if (ae->_dstid != ipa) {
		//click_chatter("the element is %x%x%x%x", ae->_dstid.data()[0],ae->_dstid.data()[1], ae->_dstid.data()[2], ae->_dstid.data()[3]);	
		ae = ae->next;
	   }else  break;
  	}
	//if (!ae) return 0;

	struct click_ip6 *ip6h;
	struct ip6_dest *ip6dst;
	struct lorif_himalis *himalis;
	unsigned length;
	unsigned char nextheader;
	IP6Address saddr, daddr;

	// get the length of the origin packet
	ip6h = (click_ip6 *)(p->data());

	// derive the packet size directly from the packet length function, instead of use ip6h->ip6_len
	length = p->length();

	nextheader = ip6h->ip6_nxt;
	//click_chatter("%{element}: next header of original packet is %x length is %d", this, nextheader,length );
	/* save the source and dest IPv6 addresses */
	memcpy(&saddr, &ip6h->ip6_src, 16);
	memcpy(&daddr, &ip6h->ip6_dst, 16);

 	//click_chatter("source ip address is %x%x::%x%x", saddr.data()[0], saddr.data()[1], saddr.data()[2], saddr.data()[3]);
      // make a packet by adding 3 extended headers.
      // The Payload Length field (16 bits) is the length of the IPv6 packet payload
      // (data field) in bytes, not counting the standard packet header
      // (as it is in IPv4 Total Length). However, the Payload Length DOES
      // include the size of any extension headers, which doesn't even exist in IPv4.
      //
      WritablePacket *q = Packet::make(length + sizeof(*ip6dst) + sizeof(*himalis) ); // adding destination and himalis extension headers

      // prepare an ipv6 header
      ip6h = reinterpret_cast<click_ip6 *>(q->data());

      ip6h->ip6_nxt = IPV6_DESTINATION;  // ip6 destination extension header

      uint32_t flow = 0;
      ip6h->ip6_flow = htonl((6 << IP6_V_SHIFT) | (0 << IP6_CLASS_SHIFT) | flow);
      ip6h->ip6_hlim = 64;

      // add the source and destination loclists
      memcpy(ip6h->ip6_src.s6_addr, _my_loclist.data(), 16);
      memcpy(ip6h->ip6_dst.s6_addr, ae->_loclist.data(), 16);

      ip6h->ip6_plen = htons(sizeof(*ip6dst) + sizeof(*himalis) + length - 40 );
      q->set_ip6_header(ip6h, sizeof(click_ip6));
      SET_DST_IP6_ANNO(q, ip6h->ip6_dst);

      // prepare a destination extended header
      ip6dst = reinterpret_cast<ip6_dest *>(ip6h + 1);
      ip6dst->ip6d_nxt = HIMALIS_HEADER;  // 0xf8 himalis extension header
      // we must define the option type and option length, otherwise, we will get unrecongized option error
      ip6dst->ip6d_reserved = htons(0x0324);  // 0x03 is the option type, and 0x24 is the length of the option
      ip6dst->ip6d_len = 4;  // the destination option header contains two loclists

      ip6dst->ip6d_encap_type = LORIF_OUTGOING; // this will be an outgoing lorif packet with 249

      memcpy(ip6dst->srcfix.s6_addr, _my_loclist.data(),16);
      memcpy(ip6dst->dstfix.s6_addr, ae->_loclist.data(), 16);

      // prepare a himalis extended header
      himalis = reinterpret_cast<lorif_himalis *>(ip6dst + 1);
      // set up HIMALIS header
      himalis->hi_nxt = nextheader;  // 17 = 0x11
      himalis->hi_len = 4;
      himalis->hi_type = 0;
      himalis->hi_ver = 1;
      himalis->hi_sum = 0;
      himalis->hi_control = 0;
      // we use the source and destination ipv6 addresses as himalis IDs
      himalis->hi_src = saddr;
      himalis->hi_dst = daddr;

      q->set_himalis_header(himalis, sizeof(himalis));

      // copy the rest part of original packet to the new packet
      int offset = sizeof(*ip6h) + sizeof(*ip6dst) + sizeof(*himalis);
      memcpy((unsigned char *) q->data() + offset, (unsigned char *) p->data()+ sizeof(*ip6h), length -  sizeof(*ip6h));

      //click_chatter("%{element}: the size of payload is %d", this, (length - 40));
      //ae->p->kill();
      //p->kill();
      output(0).push(q);
}

/*
 * The incoming packet format is
 * IPv6 header + destination extension header + himalis header
 * the output is a regular IPv6 packet without destination extension and himalis header
 */
void
LorifAgent::loclist_decap(Packet *p)
{
	struct click_ip6 *ip6h;
	struct ip6_dest *ip6dst;
	struct lorif_himalis *himalis;
	IP6Address dstid, srcid, dstloc, srcloc;
	int islorif, length;
	int nextheader, bucket;

	length = bucket = 0;
	if (p->length() < sizeof(sizeof(click_ip6) + sizeof(ip6_dest) + sizeof(lorif_himalis)))
	    return;
	length = p->length();

	// derive ip6 header and the other two headers
	ip6h = (click_ip6 *)p->data();
	ip6dst = (ip6_dest *)(ip6h + 1);

	// verify if this incoming packet is a lorif intra-packet
	// ip6 destination extension header is used to indicate the flag
	if(ip6dst->ip6d_encap_type != LORIF_TOHOST)
		return;
	//click_chatter("the target is the host");
    // get the source and destination IDs (source Himalis IDs?)
	himalis = (lorif_himalis *)(ip6dst + 1);
	nextheader = himalis->hi_nxt;
	memcpy(dstid.data(), himalis->hi_dst.s6_addr, 16);
	memcpy(srcid.data(), himalis->hi_src.s6_addr, 16);

	// get the loclists
	memcpy(srcloc.data(), ip6dst->srcfix.s6_addr, 16);
	memcpy(dstloc.data(), ip6dst->dstfix.s6_addr, 16);

	bucket = (srcid.data()[0] + srcid.data()[15]) % NMAP;
	// verify the destination ID is the host's ID
	LocEntry *lol = _ltable[bucket];
	//click_chatter("bucket is %d, dstid is %x, my_ip6 is %x", bucket, dstid.data32()[0], _my_ip6.data32()[0]);

	if(lol && dstid == _my_ip6) {
		//click_chatter("updating the loclist cache");
		// update the cache for the src id
		// here, we simply overwirte the previous one. We may change this later.
		while (lol && lol->_dstid != srcid)
			lol = lol->next;
		if (!lol)
			return;

		if (lol->_loclist != srcloc)
		lol->_loclist = srcloc;
	}


	// remove the extension headers, and return a regular IP6 packet
    WritablePacket *q = Packet::make(length - 80);
    //click_chatter("%{element}: the original packet size is %d, and the decaped size is %d", this, length, q->length());

	// prepare an ipv6 header
	ip6h = reinterpret_cast<click_ip6 *>(q->data());
	int offset = sizeof(*ip6h) + sizeof(*ip6dst) + sizeof(*himalis);

	ip6h->ip6_nxt = nextheader;  // ip6 destination extension header
	uint32_t flow = 0;
	ip6h->ip6_flow = htonl((6 << IP6_V_SHIFT) | (0 << IP6_CLASS_SHIFT) | flow);
	ip6h->ip6_hlim = 64;
        ip6h->ip6_plen = htons(length - 120);

    // return the original source and destination ids
    memcpy(ip6h->ip6_src.s6_addr, srcid.data(), 16);
    memcpy(ip6h->ip6_dst.s6_addr, dstid.data(), 16);

    // copy the rest part of original packet to the new packet
    memcpy((unsigned char *) q->data() + sizeof(*ip6h), (unsigned char *) p->data() + offset, (length - offset));
    q->set_ip6_header(ip6h, sizeof(click_ip6));

	output(1).push(q);
}

void
LorifAgent::push(int port, Packet *p)
{
   if (port == 0){
     //click_chatter("from port 0");

     loclist_encap(p);
   }else {
	if (port == 1) {
		//click_chatter("from port 1");
		loclist_decap(p);
	}else {
		p->kill();
	}
  }
}

String
LorifAgent::read_handler(Element *e, void *user_data)
{
	LorifAgent *db = (LorifAgent*) e;
    StringAccum sa;

    sa << "Local HID: " << db->_my_ip6 << '\n'
    		<< "Local LocList: " << db->_my_loclist << '\n';

    for (int i = 0; i < NMAP; i++) {
    	LocEntry *ltable = (LocEntry *) db->_ltable[i];
    	while(ltable) {
    	    sa << "Remote HID: " << ltable->_dstid << " Remote LocList: " << ltable->_loclist << '\n';
    		ltable = ltable->next;
    	}
    }
    return sa.take_string();
}

int
LorifAgent::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{
	LorifAgent *locl = (LorifAgent*) e;

    Vector<String> words;
    cp_spacevec(str, words);
    IP6Address dstid, loclist;
    int num;

    switch (reinterpret_cast<uintptr_t>(user_data)) {
      case h_insert: {
    	  if (Args(words, locl, errh)
			  .read_mp("HID", dstid)
			  .read_mp("LocList", loclist)
			  .complete() < 0)
    		  return -1;
    	  locl->insert(dstid, loclist);
    	  return 0;
      }
      case h_delete: {
    	  if (Args(words, locl, errh).read_mp("HID", dstid)
	      .complete() < 0)
    		  return -1;
    	  locl->remove_route(dstid);
    	  return 0;
      }
      case h_set: {
    	  if(Args(words, locl, errh)
    		.read_mp("IP", locl->_my_ip6)
    		.read_mp("LocList", locl->_my_loclist)
    		.execute() <0)
    		  return -1;
    	  return 0;
      }
      case h_clear:
    	  locl->clear();
    	  return 0;
      default:
    	  return -1;
    }
}

void
LorifAgent::clear()
{
    // Walk the loclist cache table and free any stored loclist entries.
	for (int i = 0; i < NMAP; i++)
		_ltable[i] = 0;
}

void
LorifAgent::add_handlers()
{
    add_read_handler("table", read_handler, 0);
    add_write_handler("add", write_handler, h_insert);
    add_write_handler("set", write_handler, h_set);
    add_write_handler("remove", write_handler, h_delete);
    add_write_handler("clear", write_handler, h_clear);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(ip6)
EXPORT_ELEMENT(LorifAgent)
