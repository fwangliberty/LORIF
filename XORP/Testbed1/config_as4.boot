/* $XORP: xorp/rtrmgr/config/click.boot,v 1.1 2007/08/29 06:49:43 pavlin Exp $ */

interfaces {
    interface eth1 {
        vif eth1 {
			address 192.168.3.3 {
				prefix-length: 24
		        broadcast: 192.168.3.255
		        disable: false
		   		}
		        /* address 2002:db8:600:3::1404 {
		        	prefix-length: 61
		        	disable: false
		        }*/
		        address fe80::a00:27ff:fed8:0405 {
		       	 	prefix-length: 64
		        }
        }
    }
    interface eth2 {
        vif eth2 {
	        address 192.168.5.1 {
	        	prefix-length: 24
	        	broadcast: 192.168.5.255
	        	disable: false
	        }
	        /* address 2002:db8:602:1::2801 {
	        	prefix-length: 61
	        	disable: false
	        }*/
	        address fe80::a00:27ff:fe0f:9887 {
	        	prefix-length: 64
	        }
        }
    }

    /* define a loopback interface */
    interface lo {
        vif lo {
           address 127.0.0.1 {
             prefix-length: 8
             broadcast: 127.255.255.255
             disable: false
           }
           address ::1 {
             prefix-length: 128
             disable: false
           }
        }
    }  
}

protocols {
    bgp {
       bgp-id:192.168.5.1
       local-as: 4
       
       peer 192.168.3.1 {
          local-ip: 192.168.3.3
          as: 2
          next-hop: 192.168.3.3
          next-hop6: fe80::a00:27ff:fed8:0405
          local-port:179
          peer-port: 179
          ipv4-multicast: true
          ipv6-unicast: true
          ipv6-multicast: true
       }
       peer 192.168.5.2 {
          local-ip: 192.168.5.1
          as: 6
          next-hop: 192.168.5.1
          next-hop6: fe80::a00:27ff:fe0f:9887
          local-port: 179
          peer-port: 179
          ipv4-multicast: true
          ipv6-unicast: true
          ipv6-multicast: true
       } 
       peer 192.168.5.3 {
          local-ip: 192.168.5.1
          as: 7
          next-hop: 192.168.5.1
          next-hop6: fe80::a00:27ff:fe0f:9887
          local-port: 179
          peer-port: 179
          ipv4-multicast: true
          ipv6-unicast: true
          ipv6-multicast: true
       }
    }
}

protocols {
    static { 
       route 8200::/9 {
           next-hop: ::1
           metric: 1
       }
       interface-route fe80::a00:27ff:fee5:e393/128 {
           next-hop-interface: "eth1"
           next-hop-vif: "eth1"
           metric: 100
       }
       interface-route fe80::a00:27ff:fe79:91d9/128 {
           next-hop-interface: "eth2"
           next-hop-vif: "eth2"
           metric: 100
       }
       interface-route fe80::a00:27ff:fe56:fc80/128 {
           next-hop-interface: "eth2"
           next-hop-vif: "eth2"
           metric: 100
       }
    }
}

policy {
   policy-statement "static-to-bgp" {
     term a {
        from {
          protocol: "static"
          metric: 1
        }
        then {
           med: 20
           accept
        }
     }
   }

   policy-statement "export-policy" {
      term a {
         from {
           protocol: "bgp"
           as-path: "6"
         }
         then {
           reject
         }
      }
      term b {
         from {
           protocol: "bgp"
           as-path: "7"
         }
         then {
          reject
         }
      }
   }
}

protocols {
   bgp { 
        export: "static-to-bgp,export-policy"
   }
}


fea {
    unicast-forwarding4 {
	disable: false
    }

    click {
	/*
	 * The Click forwarding path.
	 * http://www.read.cs.ucla.edu/click/
	 */
	disable: false

	/*
	 * Set duplicate-routes-to-kernel to true if the XORP routes
	 * added to Click should be added to the system kernel as well.
	 */
	duplicate-routes-to-kernel: false

	/*
	 * Note: If both kernel-click and user-click are enabled, then
	 * typically kernel-click-config-generator-file and
	 * user-click-config-generator-file should point to different
	 * generators. Otherwise, a single common generator
	 * wouldn't know whether to generate configuration for kernel-level
	 * Click or for user-level Click.
	 */
	kernel-click {
	    disable: true
	    install-on-startup:	true
	    kernel-click-modules: "/path/to/proclikefs.o:/path/to/click.o"
	    /* XXX: On FreeBSD we need only module click.ko */
	    /* kernel-click-modules: "/path/to/click.ko" */
	    mount-directory: "/click"
	    kernel-click-config-generator-file: "/u02/liberty/xorp/fea/xorp_fea_click_config_generator"
	}

	user-click {
	    disable: false
	    command-file: "/usr/local/bin/click"
	    /*
	     * Note: don't add "-p <port>" as an extra argument, because it
	     * will be in conflict with the FEA's addition of the same
	     * argument.
	     */
	    command-extra-arguments: "-R"
	    command-execute-on-startup: true
	    control-address: 127.0.0.1
	    control-socket-port: 13000
	    startup-config-file: "/dev/null"
	    user-click-config-generator-file: "/u02/liberty/xorp/fea/xorp_fea_click_config_generator"
	}
    }
}

 
