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

  /dst/                  { [:DST, text] }
  /src/                  { [:SRC, text] }

  /link|ether|ppp|slip/  { [:LINK, text]  }
  /fddi|tr|wlan/         { [:LINK, text]  }
  /arp/                  { [:ARP, text]   }
  /rarp/                 { [:RARP, text]  }
  /ip/                   { [:IP, text]    }
  /sctp/                 { [:SCTP, text]  }
  /tcp/                  { [:TCP, text]   }
  /udp/                  { [:UDP, text]   }
  /icmp/                 { [:ICMP, text]  }
  /igmp/                 { [:IGMP, text]  }
  /igrp/                 { [:IGRP, text]  }
  /pim/                  { [:PIM, text]   }
  /vrrp/                 { [:VRRP, text]  }
  /carp/                 { [:CARP, text]  }
  /radio/                { [:RADIO, text] }

  /ip6/                  { [:IPV6, text]   }
  /icmp6/                { [:ICMPV6, text] }
  /ah/                   { [:AH, text]     }
  /esp/                  { [:ESP, text]    }

  /atalk/                { [:ATALK, text]  }
  /aarp/                 { [:AARP, text]   }
  /decnet/               { [:DECNET, text] }
  /lat/                  { [:LAT, text]    }
  /sca/                  { [:SCA, text]    }
  /moprc/                { [:MOPRC, text]  }
  /mopdl/                { [:MOPDL, text]  }

  /iso/                  { [:ISO, text]  }
  /esis/                 { [:ESIS, text] }
  /es-is/                { [:ESIS, text] }
  /isis/                 { [:ISIS, text] }
  /is-is/                { [:ISIS, text] }
  /l1/                   { [:L1, text]   }
  /l2/                   { [:L2, text]   }
  /iih/                  { [:IIH, text]  }
  /lsp/                  { [:LSP, text]  }
  /snp/                  { [:SNP, text]  }
  /csnp/                 { [:CSNP, text] }
  /psnp/                 { [:PSNP, text] }

  /clnp/                 { [:CLNP, text] }

  /stp/                  { [:STP, text] }

  /ipx/                  { [:IPX, text] }

  /netbeui/              { [:NETBEUI, text] }

  /host/                 { [:HOST, text]       }
  /net/                  { [:NET, text]        }
  /mask/                 { [:NETMASK, text]    }
  /port/                 { [:PORT, text]       }
  /portrange/            { [:PORTRANGE, text]  }
  /proto/                { [:PROTO, text]      }
  /protochain/           { [:PROTOCHAIN, text] }

  /gateway/              { [:GATEWAY, text] }

  /type/                 { [:TYPE, text]    }
  /subtype/              { [:SUBTYPE, text] }
  /direction|dir/        { [:DIR, text]     }
  /address1|addr1/       { [:ADDR1, text]   }
  /address2|addr2/       { [:ADDR2, text]   }
  /address3|addr3/       { [:ADDR3, text]   }
  /address4|addr4/       { [:ADDR4, text]   }
  /ra/                   { [:RA, text]      }
  /ta/                   { [:TA, text]      }

  /less/                 { [:LESS, text]         }
  /greater/              { [:GREATER, text]      }
  /byte/                 { [:CBYTE, text]        }
  /broadcast/            { [:TK_BROADCAST, text] }
  /multicast/            { [:TK_MULTICAST, text] }

  /and|&&/               { [:AND, text] }
  /or|\|\|/              { [:OR, text] }
  /not/                  { [:NOT, text] }

  /len|length/           { [:LEN, text]      }
  /inbound/              { [:INBOUND, text]  }
  /outbound/             { [:OUTBOUND, text] }

  /vlan/                 { [:VLAN, text]        }
  /mpls/                 { [:MPLS, text]        }
  /pppoed/               { [:PPPOED, text]      }
  /pppoes/               { [:PPPOES, text]      }

  /lane/                 { [:LANE, text]        }
  /llc/                  { [:LLC, text]         }
  /metac/                { [:METAC, text]       }
  /bcc/                  { [:BCC, text]         }
  /oam/                  { [:OAM, text]         }
  /oamf4/                { [:OAMF4, text]       }
  /oamf4ec/              { [:OAMF4EC, text]     }
  /oamf4sc/              { [:OAMF4SC, text]     }
  /sc/                   { [:SC, text]          }
  /ilmic/                { [:ILMIC, text]       }
  /vpi/                  { [:VPI, text]         }
  /vci/                  { [:VCI, text]         }
  /connectmsg/           { [:CONNECTMSG, text]  }
  /metaconnect/          { [:METACONNECT, text] }

  /on|ifname/            { [:PF_IFNAME, text] }
  /rset|ruleset/         { [:PF_RSET, text]   }
  /rnr|rulenum/          { [:PF_RNR, text]    }
  /srnr|subrulenum/      { [:PF_SRNR, text]   }
  /reason/               { [:PF_REASON, text] }
  /action/               { [:PF_ACTION, text] }

  /fisu/                 { [:FISU, text]  }
  /lssu/                 { [:LSSU, text]  }
  /lsu/                  { [:LSSU, text]  }
  /msu/                  { [:MSU, text]   }
  /hfisu/                { [:HFISU, text] }
  /hlssu/                { [:HLSSU, text] }
  /hmsu/                 { [:HMSU, text]  }
  /sio/                  { [:SIO, text]   }
  /opc/                  { [:OPC, text]   }
  /dpc/                  { [:DPC, text]   }
  /sls/                  { [:SLS, text]   }
  /hsio/                 { [:HSIO, text]  }
  /hopc/                 { [:HOPC, text]  }
  /hdpc/                 { [:HDPC, text]  }
  /hsls/                 { [:HSLS, text]  }

  /[ \r\n\t]/            { nil  }
  /[+*\/:\[\]!<>()&|=-]/ { text }
  />=/                   { [:GEQ, text] }
  /<=/                   { [:LEQ, text] }
  /!=/                   { [:NEQ, text] }
  /==/                   { '='  }
  /<</                   { [:LSH, text] }
  />>/                   { [:RSH, text] }

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
  /\$#{B}/               { [:AID, text.to_i] } # { yyval.e = pcap_ether_aton(yytext+1); }
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

