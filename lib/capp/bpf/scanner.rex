# Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
#   The Regents of the University of California.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that: (1) source code distributions
# retain the above copyright notice and this paragraph in its entirety, (2)
# distributions including binary code include the above copyright notice and
# this paragraph in its entirety in the documentation or other materials
# provided with the distribution, and (3) all advertising materials mentioning
# features or use of this software display the following acknowledgement:
# ``This product includes software developed by the University of California,
# Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
# the University nor the names of its contributors may be used to endorse
# or promote products derived from this software without specific prior
# written permission.
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

##
# Scanner for the Berkeley Packet Filter

class Capp::BPF::Scanner < Capp::BPF

option

  do_parse
  lineno

macro
  N      /[0-9]+|(0X|0x)[\h]+/
  B      /[\h][\h]?/
  B2     /[\h][\h][\h][\h]/
  W      /[\h][\h]?[\h]?[\h]?/

  V680   /#{W}:#{W}:#{W}:#{W}:#{W}:#{W}:#{W}:#{W}/

  V670   /::#{W}:#{W}:#{W}:#{W}:#{W}:#{W}:#{W}/
  V671   /#{W}::#{W}:#{W}:#{W}:#{W}:#{W}:#{W}/
  V672   /#{W}:#{W}::#{W}:#{W}:#{W}:#{W}:#{W}/
  V673   /#{W}:#{W}:#{W}::#{W}:#{W}:#{W}:#{W}/
  V674   /#{W}:#{W}:#{W}:#{W}::#{W}:#{W}:#{W}/
  V675   /#{W}:#{W}:#{W}:#{W}:#{W}::#{W}:#{W}/
  V676   /#{W}:#{W}:#{W}:#{W}:#{W}:#{W}::#{W}/
  V677   /#{W}:#{W}:#{W}:#{W}:#{W}:#{W}:#{W}::/

  V660   /::#{W}:#{W}:#{W}:#{W}:#{W}:#{W}/
  V661   /#{W}::#{W}:#{W}:#{W}:#{W}:#{W}/
  V662   /#{W}:#{W}::#{W}:#{W}:#{W}:#{W}/
  V663   /#{W}:#{W}:#{W}::#{W}:#{W}:#{W}/
  V664   /#{W}:#{W}:#{W}:#{W}::#{W}:#{W}/
  V665   /#{W}:#{W}:#{W}:#{W}:#{W}::#{W}/
  V666   /#{W}:#{W}:#{W}:#{W}:#{W}:#{W}::/

  V650   /::#{W}:#{W}:#{W}:#{W}:#{W}/
  V651   /#{W}::#{W}:#{W}:#{W}:#{W}/
  V652   /#{W}:#{W}::#{W}:#{W}:#{W}/
  V653   /#{W}:#{W}:#{W}::#{W}:#{W}/
  V654   /#{W}:#{W}:#{W}:#{W}::#{W}/
  V655   /#{W}:#{W}:#{W}:#{W}:#{W}::/

  V640   /::#{W}:#{W}:#{W}:#{W}/
  V641   /#{W}::#{W}:#{W}:#{W}/
  V642   /#{W}:#{W}::#{W}:#{W}/
  V643   /#{W}:#{W}:#{W}::#{W}/
  V644   /#{W}:#{W}:#{W}:#{W}::/

  V630   /::#{W}:#{W}:#{W}/
  V631   /#{W}::#{W}:#{W}/
  V632   /#{W}:#{W}::#{W}/
  V633   /#{W}:#{W}:#{W}::/

  V620   /::#{W}:#{W}/
  V621   /#{W}::#{W}/
  V622   /#{W}:#{W}::/

  V610   /::#{W}/
  V611   /#{W}::/

  V600   /::/

  V6604  /#{W}:#{W}:#{W}:#{W}:#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/

  V6504  /::#{W}:#{W}:#{W}:#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6514  /#{W}::#{W}:#{W}:#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6524  /#{W}:#{W}::#{W}:#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6534  /#{W}:#{W}:#{W}::#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6544  /#{W}:#{W}:#{W}:#{W}::#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6554  /#{W}:#{W}:#{W}:#{W}:#{W}::#{N}\.#{N}\.#{N}\.#{N}/

  V6404  /::#{W}:#{W}:#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6414  /#{W}::#{W}:#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6424  /#{W}:#{W}::#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6434  /#{W}:#{W}:#{W}::#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6444  /#{W}:#{W}:#{W}:#{W}::#{N}\.#{N}\.#{N}\.#{N}/

  V6304  /::#{W}:#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6314  /#{W}::#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6324  /#{W}:#{W}::#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6334  /#{W}:#{W}:#{W}::#{N}\.#{N}\.#{N}\.#{N}/

  V6204  /::#{W}:#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6214  /#{W}::#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6224  /#{W}:#{W}::#{N}\.#{N}\.#{N}\.#{N}/

  V6104  /::#{W}:#{N}\.#{N}\.#{N}\.#{N}/
  V6114  /#{W}::#{N}\.#{N}\.#{N}\.#{N}/

  V6004  /::#{N}\.#{N}\.#{N}\.#{N}/

  V6     /#{V680}|#{V670}|#{V671}|#{V672}|#{V673}|#{V674}|#{V675}|#{V676}|#{V677}|#{V660}|#{V661}|#{V662}|#{V663}|#{V664}|#{V665}|#{V666}|#{V650}|#{V651}|#{V652}|#{V653}|#{V654}|#{V655}|#{V640}|#{V641}|#{V642}|#{V643}|#{V644}|#{V630}|#{V631}|#{V632}|#{V633}|#{V620}|#{V621}|#{V622}|#{V610}|#{V611}|#{V600}|#{V6604}|#{V6504}|#{V6514}|#{V6524}|#{V6534}|#{V6544}|#{V6554}|#{V6404}|#{V6414}|#{V6424}|#{V6434}|#{V6444}|#{V6304}|#{V6314}|#{V6324}|#{V6334}|#{V6204}|#{V6214}|#{V6224}|#{V6104}|#{V6114}|#{V6004}/

  MAC    /#{B}:#{B}:#{B}:#{B}:#{B}:#{B}|#{B}\-#{B}\-#{B}\-#{B}\-#{B}\-#{B}|#{B}\.#{B}\.#{B}\.#{B}\.#{B}\.#{B}|#{B2}\.#{B2}\.#{B2}|#{B2}#{3}/

rule

  /dst/                  { :DST }
  /src/                  { :SRC }

  /link|ether|ppp|slip/  { :LINK  }
  /fddi|tr|wlan/         { :LINK  }
  /arp/                  { :ARP   }
  /rarp/                 { :RARP  }
  /ip/                   { :IP    }
  /sctp/                 { :SCTP  }
  /tcp/                  { :TCP   }
  /udp/                  { :UDP   }
  /icmp/                 { :ICMP  }
  /igmp/                 { :IGMP  }
  /igrp/                 { :IGRP  }
  /pim/                  { :PIM   }
  /vrrp/                 { :VRRP  }
  /carp/                 { :CARP  }
  /radio/                { :RADIO }

  /ip6/                  { :IPV6   }
  /icmp6/                { :ICMPV6 }
  /ah/                   { :AH     }
  /esp/                  { :ESP    }

  /atalk/                { :ATALK  }
  /aarp/                 { :AARP   }
  /decnet/               { :DECNET }
  /lat/                  { :LAT    }
  /sca/                  { :SCA    }
  /moprc/                { :MOPRC  }
  /mopdl/                { :MOPDL  }

  /iso/                  { :ISO  }
  /esis/                 { :ESIS }
  /es-is/                { :ESIS }
  /isis/                 { :ISIS }
  /is-is/                { :ISIS }
  /l1/                   { :L1   }
  /l2/                   { :L2   }
  /iih/                  { :IIH  }
  /lsp/                  { :LSP  }
  /snp/                  { :SNP  }
  /csnp/                 { :CSNP }
  /psnp/                 { :PSNP }

  /clnp/                 { :CLNP }

  /stp/                  { :STP }

  /ipx/                  { :IPX }

  /netbeui/              { :NETBEUI }

  /host/                 { :HOST       }
  /net/                  { :NET        }
  /mask/                 { :NETMASK    }
  /port/                 { :PORT       }
  /portrange/            { :PORTRANGE  }
  /proto/                { :PROTO      }
  /protochain/           { :PROTOCHAIN }

  /gateway/              { :GATEWAY }

  /type/                 { :TYPE    }
  /subtype/              { :SUBTYPE }
  /direction|dir/        { :DIR     }
  /address1|addr1/       { :ADDR1   }
  /address2|addr2/       { :ADDR2   }
  /address3|addr3/       { :ADDR3   }
  /address4|addr4/       { :ADDR4   }
  /ra/                   { :RA      }
  /ta/                   { :TA      }

  /less/                 { :LESS         }
  /greater/              { :GREATER      }
  /byte/                 { :CBYTE        }
  /broadcast/            { :TK_BROADCAST }
  /multicast/            { :TK_MULTICAST }

  /and|&&/               { :AND }
  /or|\|\|/              { :OR }
  /not/                  { :NOT }

  /len|length/           { :LEN      }
  /inbound/              { :INBOUND  }
  /outbound/             { :OUTBOUND }

  /vlan/                 { :VLAN        }
  /mpls/                 { :MPLS        }
  /pppoed/               { :PPPOED      }
  /pppoes/               { :PPPOES      }

  /lane/                 { :LANE        }
  /llc/                  { :LLC         }
  /metac/                { :METAC       }
  /bcc/                  { :BCC         }
  /oam/                  { :OAM         }
  /oamf4/                { :OAMF4       }
  /oamf4ec/              { :OAMF4EC     }
  /oamf4sc/              { :OAMF4SC     }
  /sc/                   { :SC          }
  /ilmic/                { :ILMIC       }
  /vpi/                  { :VPI         }
  /vci/                  { :VCI         }
  /connectmsg/           { :CONNECTMSG  }
  /metaconnect/          { :METACONNECT }

  /on|ifname/            { :PF_IFNAME }
  /rset|ruleset/         { :PF_RSET   }
  /rnr|rulenum/          { :PF_RNR    }
  /srnr|subrulenum/      { :PF_SRNR   }
  /reason/               { :PF_REASON }
  /action/               { :PF_ACTION }

  /fisu/                 { :FISU  }
  /lssu/                 { :LSSU  }
  /lsu/                  { :LSSU  }
  /msu/                  { :MSU   }
  /hfisu/                { :HFISU }
  /hlssu/                { :HLSSU }
  /hmsu/                 { :HMSU  }
  /sio/                  { :SIO   }
  /opc/                  { :OPC   }
  /dpc/                  { :DPC   }
  /sls/                  { :SLS   }
  /hsio/                 { :HSIO  }
  /hopc/                 { :HOPC  }
  /hdpc/                 { :HDPC  }
  /hsls/                 { :HSLS  }

  /[ \r\n\t]/            { nil  }
  /[+*\/:\[\]!<>()&|=-]/ { text }
  />=/                   { :GEQ }
  /<=/                   { :LEQ }
  /!=/                   { :NEQ }
  /==/                   { '='  }
  /<</                   { :LSH }
  />>/                   { :RSH }

  /#{MAC}/               { [:EID, text]; } # { yyval.e = pcap_ether_aton(yytext); }
  /#{N}(\.#{N}){1,3}/    { [:HID, text] }
#                           struct addrinfo hints, *res;
#                           memset(&hints, 0, sizeof(hints));
#                           hints.ai_family = AF_INET6;
#                           hints.ai_flags = AI_NUMERICHOST;
#                           if (getaddrinfo(yytext, NULL, &hints, &res))
#                                 bpf_error("bogus IPv6 address %s", yytext);
#                           else {
#                                 freeaddrinfo(res);
#                                 yylval.s = sdup((char *)yytext); return HID6;
#                           }
  /#{V6}(?![:.\h])/      { [:HID6, text] }
  /#{B}:+(#{B}:+)+/      { raise "bogus ethernet address #{text}" }
  /#{B}/                 { [:AID, text]; } # { yyval.e = pcap_ether_aton(yytext+1); }
  /#{N}/                 { [:NUM, text.to_i] }
  /icmptype/             { [:NUM,    0] } # { yylval.i = 0; return :NUM; }
  /icmpcode/             { [:NUM,    1] } # { yylval.i = 1; return :NUM; }
  /icmp-echoreply/       { [:NUM,    0] } # { yylval.i = 0; return :NUM; }
  /icmp-unreach/         { [:NUM,    3] } # { yylval.i = 3; return :NUM; }
  /icmp-sourcequench/    { [:NUM,    4] } # { yylval.i = 4; return :NUM; }
  /icmp-redirect/        { [:NUM,    5] } # { yylval.i = 5; return :NUM; }
  /icmp-echo/            { [:NUM,    8] } # { yylval.i = 8; return :NUM; }
  /icmp-routeradvert/    { [:NUM,    9] } # { yylval.i = 9; return :NUM; }
  /icmp-routersolicit/   { [:NUM,   10] } # { yylval.i = 10; return :NUM; }
  /icmp-timxceed/        { [:NUM,   11] } # { yylval.i = 11; return :NUM; }
  /icmp-paramprob/       { [:NUM,   12] } # { yylval.i = 12; return :NUM; }
  /icmp-tstamp/          { [:NUM,   13] } # { yylval.i = 13; return :NUM; }
  /icmp-tstampreply/     { [:NUM,   14] } # { yylval.i = 14; return :NUM; }
  /icmp-ireq/            { [:NUM,   15] } # { yylval.i = 15; return :NUM; }
  /icmp-ireqreply/       { [:NUM,   16] } # { yylval.i = 16; return :NUM; }
  /icmp-maskreq/         { [:NUM,   17] } # { yylval.i = 17; return :NUM; }
  /icmp-maskreply/       { [:NUM,   18] } # { yylval.i = 18; return :NUM; }
  /tcpflags/             { [:NUM,   13] } # { yylval.i = 13; return :NUM; }
  /tcp-fin/              { [:NUM, 0x01] } # { yylval.i = 0x01; return :NUM; }
  /tcp-syn/              { [:NUM, 0x02] } # { yylval.i = 0x02; return :NUM; }
  /tcp-rst/              { [:NUM, 0x04] } # { yylval.i = 0x04; return :NUM; }
  /tcp-push/             { [:NUM, 0x08] } # { yylval.i = 0x08; return :NUM; }
  /tcp-ack/              { [:NUM, 0x10] } # { yylval.i = 0x10; return :NUM; }
  /tcp-urg/              { [:NUM, 0x20] } # { yylval.i = 0x20; return :NUM; }
  /[a-z\d]([\w.-]*[a-z\d.])?/i { [:ID, text] }
  /\\[^ !()\n\t]+/       { [:ID, text[1..-1]] } # { yylval.s = sdup(yytext + 1); return ID; }
  /[^ \[\]\t\n_.\h!<>()&|=-]+/ { raise "illegal token: #{text}" }
  /./                    { raise "illegal char '#{text}'" }

end

