#ifndef CLICK_IP6ETHERTABLE_HH
#define CLICK_IP6ETHERTABLE_HH
#include <click/etheraddress.hh>
#include <click/ip6address.hh>
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/ip6.h>
#include <clicknet/ether.h>
#include <click/gaprate.hh>
#include <click/vector.hh>

CLICK_DECLS

/*
 * =c
 * IP6EtherTable(IP61 MASK1 ETH1, IP62 MASK2 ETH2, ...)
 * =s ip6
 *
 * =d
 * Input should be a packet with ip6 header. The element query about the link layer address of the IPv6
 * target address from the table. If the element knows the answer, it adds the link layer address and 
 * forwards the packet. 
 */

class IP6EtherTable : public Element { public:

  IP6EtherTable();
  ~IP6EtherTable();

  const char *class_name() const		{ return "IP6EtherTable"; }
  const char *port_count() const		{ return PORTS_1_1; }
  int configure(Vector<String> &, ErrorHandler *);

  Packet *simple_action(Packet *);

  bool lookup(const IP6Address &, EtherAddress &deth, EtherAddress &seth) const;
  static String read_handler(Element *e, void *user_data);
  static int write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh);

  enum {
  	h_insert, h_delete, h_clear
   };

  struct Entry {
    IP6Address dst;
    IP6Address src;
    IP6Address mask;
    EtherAddress deth;
    EtherAddress seth;
  };

  Vector<Entry> _v;

  void add_map(const IP6Address &dst, const IP6Address &mask, const EtherAddress &deth, const EtherAddress &seth);
  void remove_map(const IP6Address &dst, const IP6Address &mask);
  void add_handlers();
};

CLICK_ENDDECLS
#endif
