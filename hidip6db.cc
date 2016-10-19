#include <click/config.h>
#include "hidip6db.hh"
#include <click/nameinfo.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <clicknet/udp.h>
#include <clicknet/himalis.h>


CLICK_DECLS

HIDIP6DB::HIDIP6DB()
{
}

HIDIP6DB::~HIDIP6DB()
{
}

void
HIDIP6DB::clear()
{
    // Walk the loclist cache table and free any stored loclist entries.
	for (int i = 0; i < NMAP; i++)
		_ltable[i] = 0;
}

int
HIDIP6DB::configure(Vector<String> &conf, ErrorHandler *errh)
{
	IP6Address dhid, ipv6;

	for (int i = 0; i < NMAP; i++)
			_ltable[i] = 0;

	for (int i = 0; i < conf.size(); i++) {
		dhid = IP6Address(cp_shift_spacevec(conf[i]));
		ipv6 = IP6Address(cp_shift_spacevec(conf[i]));
		//click_chatter("%{element}: inserting %dth locator %x", this, i, dstid.data32()[0]);

		if(add_route(dhid, ipv6) == -1){
			click_chatter("%{element}: insert %d locators into loclist", this, i);
			break;
		}
	}
	return 0;
}


/*
 * Packing all locators is based on group vint (proposed by google?)
 *   The first byte indicates the length of the following four locators.
 *   Note that all the locators must be byte-aligned, and less than or equal to 32 bits.
 */
int
HIDIP6DB::add_route(IP6Address dhid, IP6Address ipv6)
{
	// first find the entry from the locator table
	int bucket = (dhid.data()[0] + dhid.data()[15]) % NMAP;
	HIDEntry *ley = _ltable[bucket];
	while (ley && ley->_dhid != dhid)
	    ley = ley->next;

	if(ley) {
		// find the entry, check if ipv6 is the same address
		if(ley->_ip6 !=ipv6) {
			ley->_ip6 =ipv6;
		}else return 0;
	} else {
		// create a new entry and add it to the first element of the chain
	    HIDEntry *newley = new HIDEntry;
	    newley->_dhid = dhid;
	    newley->_ip6 =  ipv6;
	    newley->next = _ltable[bucket];
	    _ltable[bucket] = newley;
	}
}

int
HIDIP6DB::remove_route(IP6Address dhid)
{
	int bucket = (dhid.data()[0] + dhid.data()[15]) % NMAP;

	HIDEntry *ley = _ltable[bucket];
	HIDEntry *pre;

	// check if the entry from _ltable has the ID
	if(!ley) return 0;

	if(ley && ley->_dhid == dhid){
		pre = ley->next;
		_ltable[bucket] = pre;
		return 0;
	}else {
		while (ley->_dhid != dhid) {
			pre = ley;
			ley = ley->next;
		}

		if(ley){
			pre->next = ley;
		}else return 0;
	}
	return 0;
}

Packet *
HIDIP6DB::simple_action(Packet *p_in)
{
	struct click_ip6 *ip6h;
	struct ip6_dest *ip6dst;
	struct lorif_himalis *himalis;
	IP6Address dhid, ip6;

	if (p_in->length() < sizeof(sizeof(click_ip6) + sizeof(ip6_dest) + sizeof(lorif_himalis)))
		return 0;

	WritablePacket *p = p_in->uniqueify();
    if (!p)
        return 0;

	// derive ip6 header and the other two headers
	ip6h = (click_ip6 *)p->data();
	ip6dst = (ip6_dest *)(ip6h + 1);
	//click_chatter("%{element}: decap packet", this);
	// verify if this incoming packet is a lorif packet
	// ip6 destination extension header is used to indicate the flag
	if(ip6dst->ip6d_encap_type != LORIF_OUTGOING)
		return 0;
	ip6dst->ip6d_encap_type = LORIF_TOHOST;
	ip6dst->ip6d_reserved = htons(0x0324);
	// copy the loclists from ip6 header to destination header
	memcpy(ip6dst->srcfix.s6_addr, ip6h->ip6_src.s6_addr, 16);
	memcpy(ip6dst->dstfix.s6_addr, ip6h->ip6_dst.s6_addr, 16);
	// get the source and destination IDs (source Himalis IDs?)
	himalis = (lorif_himalis *)(ip6dst + 1);

	// using source HID as source IP address
	memcpy(ip6h->ip6_src.s6_addr, himalis->hi_src.s6_addr, 16);

	// mapping dest HID to dest IPv6
	dhid = IP6Address(himalis->hi_dst);
	int bucket = (dhid.data()[0] + dhid.data()[15]) % NMAP;
	HIDEntry *ae = _ltable[bucket];
	//click_chatter("search target %x at DB %x", ipa.data32()[0], ae->_dstid.data32()[0]);
	while (ae && ae->_dhid != dhid) {
		click_chatter("search target %x%x at DB %x%x",  dhid.data()[0], dhid.data()[1], ae->_dhid.data()[0], ae->_dhid.data()[1]);
		ae = ae->next;
	}
	if (!ae)
		return 0;
	ip6 = ae->_ip6;

	memcpy(&ip6h->ip6_dst, ip6.data(), 16);
	SET_DST_IP6_ANNO(p, ip6h->ip6_dst);
    p->set_ip6_header(ip6h, sizeof(click_ip6));

    return p;
}



String
HIDIP6DB::read_handler(Element *e, void *user_data)
{
    HIDIP6DB *db = (HIDIP6DB*) e;
    StringAccum sa;

    for (int i = 0; i < NMAP; i++) {
    	HIDEntry *ltable = (HIDEntry *) db->_ltable[i];
    	while(ltable) {
    	    sa << ltable->_dhid << ' ' << ltable->_ip6 << '\n';
    		ltable = ltable->next;
    	}
    }
    return sa.take_string();
}

int
HIDIP6DB::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{
	HIDIP6DB *locl = (HIDIP6DB*) e;

    Vector<String> words;
    cp_spacevec(str, words);
    IP6Address dhid, ip6;

    switch (reinterpret_cast<uintptr_t>(user_data)) {
      case h_insert: {
    	  if (Args(words, locl, errh)
			  .read_mp("HID", dhid)
			  .read_mp("IPv6", ip6)
			  .complete() < 0)
    		  return -1;
    	  locl->add_route(dhid, ip6);
    	  return 0;
      }
      case h_delete: {
    	  if (Args(words, locl, errh).read_mp("HID", dhid)
	      .complete() < 0)
    		  return -1;
    	  locl->remove_route(dhid);
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
HIDIP6DB::add_handlers()
{
    add_read_handler("table", read_handler, 0);
    add_write_handler("add", write_handler, h_insert);
    add_write_handler("remove", write_handler, h_delete);
    add_write_handler("clear", write_handler, h_clear);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(HIDIP6DB)
ELEMENT_MT_SAFE(HIDIP6DB)
// we may want implement this element on user-level
//ELEMENT_REQUIRES(linuxmodule ip6)
//ELEMENT_REQUIRES(userlevel) //linuxmodule)
