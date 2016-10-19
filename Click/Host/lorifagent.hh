#ifndef CLICK_LORIFAGENT_HH
#define CLICK_LORIFAGENT_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/ip6address.hh>
#include <click/timer.hh>
CLICK_DECLS

class LorifAgent : public Element {
 public:

  LorifAgent();
  ~LorifAgent();

  const char *class_name() const		{ return "LorifAgent"; }
  const char *port_count() const		{ return "2/2"; }
  const char *processing() const		{ return PUSH; }
  const char *flow_code() const			{ return "xy/x"; }

  void add_handlers();

  int configure(Vector<String> &, ErrorHandler *);

  void push(int port, Packet *);

  static String read_handler(Element *e, void *user_data);
  static int write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh);

  int remove_route(IP6Address dstid);
  int insert(IP6Address, IP6Address);
  void clear();

  // a table to keep locators
  struct LocEntry {
    IP6Address _dstid;
    IP6Address _loclist;
    struct LocEntry *next;
  };
  enum { NMAP = 256 };
  LocEntry *_ltable[NMAP];

  enum {
 	h_insert, h_delete, h_set, h_clear
  };

  IP6Address _my_loclist;
  IP6Address _my_ip6;

  int loclist_encap(Packet *);
  void loclist_decap(Packet *);
};

CLICK_ENDDECLS
#endif
