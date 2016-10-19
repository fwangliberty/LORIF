#ifndef CLICK_HIDIP6DB_HH
#define CLICK_HIDIP6DB_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/ip6.h>
#include <clicknet/ether.h>
#include <click/ip6address.hh>
#include <click/gaprate.hh>
#include <click/vector.hh>

CLICK_DECLS

/*
 * encapsulates a set of locators in a hop-to-hop header of an incoming himalis packet
 * the locator is in IP6Address format
 */

class HIDIP6DB : public Element { public:

  HIDIP6DB();
  ~HIDIP6DB();

  const char *class_name() const        { return "HIDIP6DB"; }
  const char *port_count() const        { return PORTS_1_1; }

  int  configure(Vector<String> &, ErrorHandler *);
  bool can_live_reconfigure() const	{ return true; }

  void add_handlers();
  void clear();

  Packet *simple_action(Packet *);

  enum {
 	h_insert, h_delete, h_clear
  };
  static String read_handler(Element *e, void *user_data);
  static int write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh);

  int add_route(IP6Address hid, IP6Address ipv6);
  int remove_route(IP6Address dstid);

  // a table to keep HIDs
  struct HIDEntry {
    IP6Address _dhid;
    IP6Address _ip6;
    struct HIDEntry *next;
  };
  enum { NMAP = 256 };
  HIDEntry *_ltable[NMAP];
};

CLICK_ENDDECLS
#endif
