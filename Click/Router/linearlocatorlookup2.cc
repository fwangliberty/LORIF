/*
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
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
#include "linearlocatorlookup2.hh"
#include <click/ip6address.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <clicknet/ip6.h>

CLICK_DECLS

LinearLocatorLookup2::LinearLocatorLookup2()
{
}

LinearLocatorLookup2::~LinearLocatorLookup2()
{
}

int
LinearLocatorLookup2::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int maxout = -1;
  _t.clear();

  for (int i = 0; i < conf.size(); i++) {
    IP6Address dst, mask, gw;
    int output_num;
    // int flag; this flag is gone because we mix both locators and ipv6 together
    bool ok = false;

    Vector<String> words;
    cp_spacevec(conf[i], words);

    if ((words.size()==2 || words.size()==3 )
      && cp_ip6_prefix(words[0], (unsigned char *)&dst, (unsigned char *)&mask, true, this)
	&& IntArg().parse(words[2], output_num) )
    {
      if (words.size()==3)
	ok = cp_ip6_address(words[1], (unsigned char *)&gw, this);
      else {
	gw = IP6Address("::0");
	ok = true;
      }
    }

  if (ok && output_num>=0) {
    _t.add(dst, mask, gw, output_num);
    if( output_num > maxout)
        maxout = output_num;
    } else {
      errh->error("argument %d should be DADDR/MASK [GW] FLAG OUTPUT", i+1);
    }
  }


  if (errh->nerrors())
    return -1;
  if (maxout <0)
    errh->warning("no routes");

  if (maxout >= noutputs())
      return errh->error("need %d or more output ports", maxout + 1);
  return 0;

}

int
LinearLocatorLookup2::initialize(ErrorHandler *)
{
  _last_addr = IP6Address();
  #ifdef IP_RT_CACHE2
  _last_addr2 = _last_addr;
#endif
  return 0;
}

bool
LinearLocatorLookup2::parser(IP6Address &a, IP6Address &gw, int &index, int &failed)
{
	IP6Address locator;
	int i, flag;
	flag = 0;

	// get the length prefix
	const uint32_t *loc = a.data32();

	for(i = 0; i < 4; i++) {
		// if the content of the locator is 0s, search the next one
		if(!loc[i]) {
			continue;
		}
		locator = uint32toip6(loc[i]);

		// locator lookup from cache
		if (locator == _last_addr     ) {
			if (_last_gw) {
				gw = _last_gw;
				index = _last_output;
				failed = flag;
				return true;
			}
		}

		if (_t.lookup(locator, gw, index)) {
			_last_addr = locator;
			_last_gw = gw;
			_last_output = index;
			failed = flag;
			return true;
		} else {
			flag = i + 1;
			if(i == 4) {
				return false;
			}
		}
	}
	return false;
}

void
LinearLocatorLookup2::push(int, Packet *p)
{
  IP6Address a = DST_IP6_ANNO(p);
  IP6Address gw;
  int ifi = -1;
  int flag;
  bool isLorif = true;

  /*
   * determine the type of the packet: a regular IP or an IP6 header with a destination extension and Himalis header.
  */
  struct ip6_dest *_ip6d;
  //const click_ip6 *ip6h = p->ip6_header();;
  const click_ip6 *ip6h = (click_ip6 *)p->data();

  if(ip6h->ip6_nxt != IPV6_DESTINATION){
		//click_chatter("Regular IPv6 packet due to next header field");
		isLorif=false;
  }else {
	  /* get the destination extension header */
	  _ip6d = (ip6_dest *) (ip6h + 1);

	  if(_ip6d->ip6d_nxt != HIMALIS_HEADER && _ip6d->ip6d_encap_type != LORIF_OUTGOING ) {
  		///click_chatter("Regular IPv6 packet due to encap type");
  		isLorif=false;
  	 }else {
	   if(_ip6d->ip6d_nxt == HIMALIS_HEADER && _ip6d->ip6d_encap_type == LORIF_TOHOST) {
                isLorif=false;
           }
	}
  }

  if(isLorif){
	  //click_chatter(" a lorif packet lookup");
	  if (parser(a, gw, ifi, flag)) {
		_last_addr = a;
		_last_gw = gw;
		_last_output = ifi;

		// determine if any of the locators does not work
		if(flag) {
			WritablePacket *q = p->uniqueify();
			// let the failed destination locator be all 0s
			// click_ip6 *ip = q->ip6_header(); // in case the packet has ip6_header()
			click_ip6 *ip6 = (click_ip6 *)(q->data());

			ip6->ip6_dst.s6_addr32[flag-1] = 0;
			//click_chatter("flag = %d, and output is %d", flag, ifi);
			// debug
			//for(int n= 0; n<16; n++)
			//	click_chatter("destionation is changed is dst[%d] = %x", n, ip6->ip6_dst.s6_addr[n] );
			if (gw != IP6Address("::0")) {
				SET_DST_IP6_ANNO(q, IP6Address(gw));
			}
			q->set_ip6_header(ip6, sizeof(click_ip6));
			output(ifi).push(q);
		}else {
			if (gw != IP6Address("::0")) {
				SET_DST_IP6_ANNO(p, IP6Address(gw));
			}
			p->set_ip6_header(ip6h, sizeof(click_ip6));
			output(ifi).push(p);
		}
	  } else {
	    p->kill();
	  }
  }else {
	  // a regular IPv6 address lookup
	  if (a) {
		  uint32_t *xi = (uint32_t *) a.data32();
		  //click_chatter("an IPv6 %x packet lookup output = %d", ntohl(xi[3]), _last_output);
		  if (a == _last_addr     ) {
			  if (_last_gw)
			  {
				  SET_DST_IP6_ANNO(p, _last_gw);
			  }
			  p->set_ip6_header(ip6h, sizeof(click_ip6));
			  output(_last_output).push(p);
			  return;
		  }
#ifdef IP_RT_CACHE2
		  else if (a == _last_addr2) {
	#if 0
      IP6address tmpa;
      int tmpi;
      EXCHANGE(_last_addr, _last_addr2, tmpa);
      EXCHANGE(_last_gw, _last_gw2, tmpa);
      EXCHANGE(_last_output, _last_output2, tmpi);
	#endif
      if (_last_gw2) {
    	  SET_DST_IP6_ANNO(p, _last_gw2);
      }
      output(_last_output2).push(p);
      return;
	}
#endif
  }

  if (_t.lookup(a, gw, ifi)) {
#ifdef IP_RT_CACHE2
    _last_addr2 = _last_addr;
    _last_gw2 = _last_gw;
    _last_output2 = _last_output;
#endif
    uint32_t *xi = (uint32_t *) gw.data32();
    //click_chatter("the IPv6 packet %x lookup successfully output = %d", ntohl(xi[0]), ifi);
    _last_addr = a;
    _last_gw = gw;
    _last_output = ifi;
    if (gw != IP6Address("::0")) {
	SET_DST_IP6_ANNO(p, IP6Address(gw));
    }
    p->set_ip6_header(ip6h, sizeof(click_ip6));
    output(ifi).push(p);
  } else {
    p->kill();
  }
  }
}

int
LinearLocatorLookup2::add_route(IP6Address addr, IP6Address mask, IP6Address gw,
                          int output, ErrorHandler *errh)
{
  if (output < 0 && output >= noutputs())
    return errh->error("port number out of range"); // Can't happen...

  _t.add(addr, mask, gw, output);
  return 0;
}

int
LinearLocatorLookup2::remove_route(IP6Address addr, IP6Address mask,
			     ErrorHandler *)
{
  _t.del(addr, mask);
  return 0;
}

void
LinearLocatorLookup2::add_handlers()
{
    add_write_handler("add", add_route_handler, 0);
    add_write_handler("remove", remove_route_handler, 0);
    add_write_handler("ctrl", ctrl_handler, 0);
    add_read_handler("table", table_handler, 0);
}

IP6Address
LinearLocatorLookup2::uint32toip6(uint32_t num)
{
	IP6Address result = IP6Address::uninitialized_t();
    uint32_t *ri = result.data32();
    ri[0] = num;
    ri[1] = 0;
    ri[2] = 0;
    ri[3] = 0;
    return result;
}


CLICK_ENDDECLS
ELEMENT_REQUIRES(LocatorTable)
EXPORT_ELEMENT(LinearLocatorLookup2)
