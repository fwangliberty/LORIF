#ifndef CLICK_LINEARLOCATORLOOKUP2_HH
#define CLICK_LINEARLOCATORLOOKUP2_HH
#include <click/element.hh>
#include "locatortable.hh"
#include "lorifroutetable.hh"
CLICK_DECLS

/*
 * LinearLocatorLookup2(DST1 MASK1 GW1 FLAG1 OUT1, DST2 MAS2 GW2 FLAG2 OUT2, ...)
 *
 * Input: IP6 packets or Lorif packets (no ether header).
 * Expects a destination IP6 address (Lorif locator) annotation with each packet.
 * Looks up the address, sets the destination annotation to
 * the corresponding GW (if non-zero), and emits the packet
 * on the indicated OUTput.
 *
 * Each comma-separated argument is a route, specifying
 * a destination and mask, a gateway (zero means none), a flag ('0' for IP6, and '1' for Lorif)
 * and an output index.
 */

class LinearLocatorLookup2 : public LORIFRouteTable {
public:
  LinearLocatorLookup2();
  ~LinearLocatorLookup2();

  const char *class_name() const		{ return "LinearLocatorLookup2"; }
  const char *port_count() const		{ return "1/-"; }
  const char *processing() const		{ return PUSH; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void add_handlers();
  bool parser(IP6Address &a, IP6Address &gw, int &index, int &failed);
  void push(int port, Packet *p);

  int add_route(IP6Address, IP6Address, IP6Address, int, ErrorHandler *);
  int remove_route(IP6Address, IP6Address, ErrorHandler *);
  String dump_routes()				{ return _t.dump(); };
  IP6Address uint32toip6(uint32_t num);

private:

  LocatorTable _t;

  IP6Address _last_addr;
  IP6Address _last_gw;
  int _last_output;

#ifdef IP_RT_CACHE2
  IPAddress _last_addr2;
  IPAddress _last_gw2;
  int _last_output2;
#endif

};

CLICK_ENDDECLS
#endif
