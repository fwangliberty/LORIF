/*
 * ip6ethertable.{cc,hh} -- element that encapsulates link layer address
 * Feng Wang
 */

#include <click/config.h>
#include "ip6ethertable.hh"
#include <clicknet/ether.h>
#include <clicknet/ip6.h>
#include <click/etheraddress.hh>
#include <click/ip6address.hh>
#include <click/args.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/nameinfo.hh>
#include <click/confparse.hh>


CLICK_DECLS

IP6EtherTable::IP6EtherTable()
{
}

IP6EtherTable::~IP6EtherTable()
{
}

void
IP6EtherTable::add_map(const IP6Address &ipa, const IP6Address &mask, const EtherAddress &deth, const EtherAddress &seth)
{
  struct Entry e;
  e.dst = ipa;
  e.mask = mask;
  e.deth = deth;
  e.seth = seth;
  _v.push_back(e);
}

void
IP6EtherTable::remove_map(const IP6Address &ipa, const IP6Address &mask)
{
  // search the vector first
  for(Vector<Entry>::iterator it = _v.begin(); it != _v.end();)
  {
	    if (ipa.matches_prefix(it->dst, it->mask)) {
		_v.erase(it);
		break;
	    }
  }
}

int
IP6EtherTable::configure(Vector<String> &conf, ErrorHandler *errh)
{
  _v.clear();

  for (int i = 0; i < conf.size(); i++) {
    IP6Address ipa, mask;
    EtherAddress deth, seth;
    int first_ena = 0;
    int first = _v.size();

    Vector<String> words;
    cp_spacevec(conf[i], words);

    for (int j = 0; j < words.size(); j++) {
      if (cp_ip6_prefix(words[j], (unsigned char *)&ipa, (unsigned char *)&mask, true, this))
    	  add_map(ipa, mask, EtherAddress(), EtherAddress());
      else if (cp_ip6_address(words[j], &ipa, this))
    	  add_map(ipa, IP6Address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), EtherAddress(), EtherAddress());
      else if (!first_ena) {
    	  EtherAddressArg().parse(words[j], seth, this);
    	  first_ena = 1;
      } else {
    	  EtherAddressArg().parse(words[j], deth, this);
    	  j = words.size();
      }
    }

    if (first == _v.size())
    		  errh->error("argument %d had no IP6 address and masks", i);
    for (int j = first; j < _v.size(); j++) {
    	  _v[j].deth = deth;
      	  _v[j].seth = seth;
    }
  }

  return errh->nerrors() ? -1 : 0;
}

 

bool
IP6EtherTable::lookup(const IP6Address &a, EtherAddress &deth, EtherAddress &seth) const
{
  int best = -1;
  for (int i = 0; i < _v.size(); i++)
    if (a.matches_prefix(_v[i].dst, _v[i].mask)) {
      if (best < 0 || _v[i].mask.mask_as_specific(_v[best].mask))
	best = i;
    }

  if (best < 0)
    return false;
  else {
    deth = _v[best].deth;
    seth = _v[best].seth;
    return true;
  }
}

Packet *
IP6EtherTable::simple_action(Packet *p)
{
   // the incoming packet must be an IPv6 packet
   click_ip6 *ip6 = (click_ip6 *) p->data();
   unsigned char dpa[16];
   memcpy(&dpa, IP6Address(ip6->ip6_dst).data(), 16);
   IP6Address ipa = IP6Address(dpa);

   EtherAddress deth, seth;

   click_ether ethh;
   if(lookup(ipa, deth, seth))
   {
      if (WritablePacket *q = p->push_mac_header(14)) {
    	  memcpy(&ethh.ether_shost, deth.data(), 6);
		  memcpy(&ethh.ether_dhost, seth.data(), 6);
		  ethh.ether_type = htons(ETHERTYPE_IP6);
		  memcpy(q->data(), &ethh, 14);
        return q;
      }else
	return 0;
   }
   else
   {
      p->kill();
      return 0;
   }
}

String
IP6EtherTable::read_handler(Element *e, void *user_data)
{
	IP6EtherTable *db = (IP6EtherTable*) e;
    StringAccum sa;

    Vector<Entry> ltable = (Vector<Entry>) db->_v;

    for (int i = 0; i < ltable.size(); i++)
	    sa << ltable[i].dst << ' ' << ltable[i].mask << ' ' << ltable[i].deth << ' ' << ltable[i].seth << '\n';

    return sa.take_string();
}

int
IP6EtherTable::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{
	IP6EtherTable *locl = (IP6EtherTable*) e;

//    Vector<String> words;
//    cp_spacevec(str, words);
    IP6Address ip6, mask;
    EtherAddress deth, seth;

    switch (reinterpret_cast<uintptr_t>(user_data)) {
      case h_insert: {
    	  if (Args(locl, errh).push_back_words(str)
			  .read_mp("IPv6", ip6)
			  .read_mp("MASK", mask)
			  .read_mp("DSTETH", deth)
			  .read_mp("SRCETH", seth)
			  .complete() < 0)
    		  return -1;
    	  locl->add_map(ip6, mask, deth, seth);
    	  return 0;
      }
      case h_delete: {
    	  if (Args(locl, errh).push_back_words(str)
    		.read_mp("IPv6", ip6)
    		.read_mp("MASK", mask)
	        .complete() < 0)
    		  return -1;
    	  locl->remove_map(ip6, mask);
    	  return 0;
      }
      case h_clear:
    	  locl->_v.clear();
    	  return 0;
      default:
    	  return -1;
    }
}

void
IP6EtherTable::add_handlers()
{
    add_read_handler("table", read_handler, 0);
    add_write_handler("add", write_handler, h_insert);
    add_write_handler("remove", write_handler, h_delete);
    add_write_handler("clear", write_handler, h_clear);
}


ELEMENT_REQUIRES(ip6)
EXPORT_ELEMENT(IP6EtherTable)
CLICK_ENDDECLS
