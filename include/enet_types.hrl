-ifndef(__ENET_TYPES_HRL__).
-define(__ENET_TYPES_HRL__, true).

-record(raw, {data :: binary()
             }).

-type ethernet_address() :: list() | << _:48 >> |
			    {uint8(),uint8(),uint8(),uint8(),uint8(),uint8()}.
-type ethertype() :: atom() | 0..65535.
-type uint32() :: 0..16#ffffffff.
-type uint16() :: 16#0000..16#ffff.
-type uint8()  :: 16#00..16#ff.

-define(is_uint8(X),  (((X) band (bnot 16#ff)) =:= 0)).
-define(is_uint16(X), (((X) band (bnot 16#ffff)) =:= 0)).


-record(eth, {src :: ethernet_address()
              ,dst :: ethernet_address()
              ,type :: ethertype()
              ,data :: term()
             }).

-type ip_proto() :: atom() | 0..255.
-type ip_address() :: ipv4_address() | ipv6_addr().
-type ipv4_address() :: localhost | << _:32 >> |
			{uint8(),uint8(),uint8(),uint8()}.
-type arp_op() :: 'request' | 'reply' | 0..65535.
-type l3_proto() :: atom() | 0..65535.

-record(arp, {htype :: ethertype()
              ,ptype :: l3_proto()
              ,haddrlen :: non_neg_integer()
              ,paddrlen :: non_neg_integer()
              ,op :: arp_op()
              ,sender :: {ethernet_address(), ipv4_address()}
              ,target :: {ethernet_address(), ipv4_address()}
             }).

-type checksum() :: 'correct' | {'incorrect', integer()} | integer().

-record(ipv4_opt, {type :: atom() | {non_neg_integer(), non_neg_integer()}
                   ,copy :: 1 | 0
                   ,data :: term()
                  }).

-type ipv4_flag() :: 'evil' | 'dont_fragment' | 'more_fragments'.
-type ipv4_flags() :: << _:3 >> | list(ipv4_flag()).
-type ipv4_option() :: #ipv4_opt{}.

-record(ipv4, {vsn = 4 :: integer()
               ,hlen :: non_neg_integer()
               ,diffserv = 0 :: integer()
               ,totlen :: non_neg_integer()
               ,id = 0 :: integer()
               ,flags = <<0:3>> :: ipv4_flags()
               ,frag_offset = 0 :: non_neg_integer()
               ,ttl = 64 :: non_neg_integer()
               ,proto :: ip_proto()
               ,hdr_csum :: checksum()
               ,src :: ipv4_address()
               ,dst :: ipv4_address()
               ,options = [] :: list(ipv4_option()) | binary()
               ,data :: term()
              }).

-type port_no() :: 0..65535 | binary().
-type netport() :: list() | port_no().

-record(udp, {src_port :: port_no()
              ,dst_port :: port_no()
              ,length :: non_neg_integer()
              ,csum :: checksum()
              ,data :: term()
             }).

-type icmp_type() :: atom() | {Type::non_neg_integer(), Code::non_neg_integer()}.

-record(icmp, {type :: icmp_type()
               ,csum :: checksum()
               ,id :: non_neg_integer()
               ,seq :: non_neg_integer()
               ,data :: binary()
              }).

-record(icmp6, {type :: icmp_type()
               ,csum :: checksum()
               ,id :: non_neg_integer()
               ,seq :: non_neg_integer()
               ,data :: binary()
              }).

-type flag_value() :: boolean() | 0..1.

-type tcp_option() :: term().

-record(tcp, {src_port :: port_no()
              ,dst_port :: port_no()
              ,seq_no :: non_neg_integer()
              ,ack_no :: non_neg_integer()
              ,data_offset :: non_neg_integer()
              ,reserved :: non_neg_integer()
              ,urg :: flag_value()
              ,ack :: flag_value()
              ,psh :: flag_value()
              ,rst :: flag_value()
              ,syn :: flag_value()
              ,fin :: flag_value()
              ,window :: 0..65535
              ,csum :: checksum()
              ,urg_pointer :: non_neg_integer()
              ,options :: binary() | [tcp_option()]
              ,data :: term()
             }).

-type af_type() :: atom() | 0..255.

-record(null, {type :: af_type(),
               data :: term()}).

-type ipv6_addr() :: localhost | << _:128 >> |
		     {uint16(),uint16(),uint16(),uint16(),
		      uint16(),uint16(),uint16(),uint16()}.

-record(ipv6, {version = 6,
               traffic_class :: non_neg_integer(),
               flow_label :: bitstring(),
               payload_len :: non_neg_integer(),
               next_hdr :: ip_proto(),
               hop_count = 255 :: 0..255,
               src :: ipv6_addr(),
               dst :: ipv6_addr(),
               payload :: term()}).

-record(ipv6_frag, {offset,
                    m,
                    id}).

-record(ipv6_route, {type, segments, addresses}).

-record(ip_pseudo_hdr, {src :: << _ : 32 >> | << _:128 >>
                       ,dst :: << _ : 32 >> | << _:128 >>
		       ,length = 0 :: 0..16#ffffffff
                       ,proto :: 0..255
                       }).

%% bootp stuff

-define(BOOTREQUEST, 1).
-define(BOOTREPLY,   2).

-define(BOOTP_BROADCAST, 16#8000).

-define(HTYPE_ETHER,   1).    %% Ethernet 10Mbps
-define(HTYPE_IEEE802, 6).    %% IEEE 802.2 Token Ring
-define(HTYPE_FDDI,    8).    %% FDDI

%%% Magic cookie validating dhcp options and bootp vendor extensions field
-define(DHCP_OPTIONS_COOKIE, 99, 130, 83, 99).

%% DHCP message type (option 53)
-define(DHCPDiscover, 1).
-define(DHCPOffer, 2).
-define(DHCPRequest, 3).
-define(DHCPDecline, 4).
-define(DHCPAck, 5).
-define(DHCPNak,6).
-define(DHCPRelease,7).
-define(DHCPInform,8).

-record(dhcp, {
	  op,                       %% Message opcode
	  htype   = ?HTYPE_ETHER,   %% Hardware addr type
	  hlen    = 6,              %% Hardware addr length
	  hops    = 0,              %% Number of relay agent hops from client
	  xid     = 0,              %% Transaction ID
	  secs    = 0,              %% Seconds since client started looking
	  flags   = 0,              %% Flag bits
	  ciaddr  = {0,0,0,0},      %% Client IP address (if already in use)
	  yiaddr  = {0,0,0,0},      %% Client IP address
	  siaddr  = {0,0,0,0},      %% IP address of next server to talk to
	  giaddr  = {0,0,0,0},      %% DHCP relay agent IP address
	  chaddr  = {0,0,0,0,0,0},  %% Client hardware address
	  sname   = [],             %% Server name
	  file    = [],             %% Boot filename
	  options = []              %% Optional parameters
	 }).

%%% DHCP Option codes
-define(DHO_PAD,                          0).
-define(DHO_SUBNET_MASK,                  1).
-define(DHO_TIME_OFFSET,                  2).
-define(DHO_ROUTERS,                      3).
-define(DHO_TIME_SERVERS,                 4).
-define(DHO_NAME_SERVERS,                 5).
-define(DHO_DOMAIN_NAME_SERVERS,          6).
-define(DHO_LOG_SERVERS,                  7).
-define(DHO_COOKIE_SERVERS,               8).
-define(DHO_LPR_SERVERS,                  9).
-define(DHO_IMPRESS_SERVERS,             10).
-define(DHO_RESOURCE_LOCATION_SERVERS,   11).
-define(DHO_HOST_NAME,                   12).
-define(DHO_BOOT_SIZE,                   13).
-define(DHO_MERIT_DUMP,                  14).
-define(DHO_DOMAIN_NAME,                 15).
-define(DHO_SWAP_SERVER,                 16).
-define(DHO_ROOT_PATH,                   17).
-define(DHO_EXTENSIONS_PATH,             18).
-define(DHO_IP_FORWARDING,               19).
-define(DHO_NON_LOCAL_SOURCE_ROUTING,    20).
-define(DHO_POLICY_FILTER,               21).
-define(DHO_MAX_DGRAM_REASSEMBLY,        22).
-define(DHO_DEFAULT_IP_TTL,              23).
-define(DHO_PATH_MTU_AGING_TIMEOUT,      24).
-define(DHO_PATH_MTU_PLATEAU_TABLE,      25).
-define(DHO_INTERFACE_MTU,               26).
-define(DHO_ALL_SUBNETS_LOCAL,           27).
-define(DHO_BROADCAST_ADDRESS,           28).
-define(DHO_PERFORM_MASK_DISCOVERY,      29).
-define(DHO_MASK_SUPPLIER,               30).
-define(DHO_ROUTER_DISCOVERY,            31).
-define(DHO_ROUTER_SOLICITATION_ADDRESS, 32).
-define(DHO_STATIC_ROUTES,               33).
-define(DHO_TRAILER_ENCAPSULATION,       34).
-define(DHO_ARP_CACHE_TIMEOUT,           35).
-define(DHO_IEEE802_3_ENCAPSULATION,     36).
-define(DHO_DEFAULT_TCP_TTL,             37).
-define(DHO_TCP_KEEPALIVE_INTERVAL,      38).
-define(DHO_TCP_KEEPALIVE_GARBAGE,       39).
-define(DHO_NIS_DOMAIN,                  40).
-define(DHO_NIS_SERVERS,                 41).
-define(DHO_NTP_SERVERS,                 42).
-define(DHO_VENDOR_ENCAPSULATED_OPTIONS, 43).
-define(DHO_NETBIOS_NAME_SERVERS,        44).
-define(DHO_NETBIOS_DD_SERVERS,          45).
-define(DHO_NETBIOS_NODE_TYPE,           46).
-define(DHO_NETBIOS_SCOPE,               47).
-define(DHO_FONT_SERVERS,                48).
-define(DHO_X_DISPLAY_MANAGERS,          49).
-define(DHO_DHCP_REQUESTED_ADDRESS,      50).
-define(DHO_DHCP_LEASE_TIME,             51).
-define(DHO_DHCP_OPTION_OVERLOAD,        52).
-define(DHO_DHCP_MESSAGE_TYPE,           53).
-define(DHO_DHCP_SERVER_IDENTIFIER,      54).
-define(DHO_DHCP_PARAMETER_REQUEST_LIST, 55).
-define(DHO_DHCP_MESSAGE,                56).
-define(DHO_DHCP_MAX_MESSAGE_SIZE,       57).
-define(DHO_DHCP_RENEWAL_TIME,           58).
-define(DHO_DHCP_REBINDING_TIME,         59).
-define(DHO_VENDOR_CLASS_IDENTIFIER,     60).
-define(DHO_DHCP_CLIENT_IDENTIFIER,      61).
-define(DHO_NWIP_DOMAIN_NAME,            62).  %% rfc2242
-define(DHO_NWIP_SUBOPTIONS,             63).  %% rfc2242
-define(DHO_NIS_PLUS_DOMAIN,             64).  %% rfc2132
-define(DHO_NIS_PLUS_SERVERS,            65).  %% rfc2132
-define(DHO_TFTP_SERVER_NAME,            66).  %% rfc2132
-define(DHO_BOOTFILE_NAME,               67).  %% rfc2132
-define(DHO_MOBILE_IP_HOME_AGENTS,       68).
-define(DHO_SMTP_SERVERS,                69).
-define(DHO_POP3_SERVERS,                70).
-define(DHO_NNTP_SERVERS,                71).
-define(DHO_WWW_SERVERS,                 72).
-define(DHO_FINGER_SERVERS,              73).
-define(DHO_IRC_SERVERS,                 74).
-define(DHO_STREETTALK_SERVERS,          75).
-define(DHO_STDA_SERVERS,                76).
-define(DHO_USER_CLASS,                  77). %% rfc3004
-define(DHO_FQDN,                        81). %% draft-ietf-dhc-fqdn-option-10
-define(DHO_DHCP_AGENT_OPTIONS,          82). %% rfc3046
-define(DHO_NDS_SERVERS,                 85). %% rfc2241
-define(DHO_NDS_TREE_NAME,               86). %% rfc2241
-define(DHO_NDS_CONTEXT,                 87). %% rfc2241
-define(DHO_UAP,                         98). %% rfc2485
-define(DHO_AUTO_CONFIGURE,             116). %% rfc2563
-define(DHO_NAME_SERVICE_SEARCH,        117). %% rfc2937
-define(DHO_SUBNET_SELECTION,           118). %% rfc3011
-define(DHO_TFTP_SERVER_ADDRESS,        150). %% rfc5859
-define(DHO_END,                        255).

%%% DHCP Message types
-define(DHCPDISCOVER, 1).
-define(DHCPOFFER,    2).
-define(DHCPREQUEST,  3).
-define(DHCPDECLINE,  4).
-define(DHCPACK,      5).
-define(DHCPNAK,      6).
-define(DHCPRELEASE,  7).
-define(DHCPINFORM,   8).

%%% Relay Agent Information option subtypes
-define(RAI_CIRCUIT_ID, 1).
-define(RAI_REMOTE_ID,  2).
-define(RAI_AGENT_ID,   3).

%%% FQDN suboptions
-define(FQDN_NO_CLIENT_UPDATE, 1).
-define(FQDN_SERVER_UPDATE,    2).
-define(FQDN_ENCODED,          3).
-define(FQDN_RCODE1,           4).
-define(FQDN_RCODE2,           5).
-define(FQDN_HOSTNAME,         6).
-define(FQDN_DOMAINNAME,       7).
-define(FQDN_FQDN,             8).
-define(FQDN_SUBOPTION_COUNT,  8).

%%
%% DNS type from kernel/src/inet_dns.hrl not always present in all distros
%%

%%
%% Currently defined opcodes
%%
-define(QUERY,    16#0).          %% standard query
-define(IQUERY,   16#1).	      %% inverse query
-define(STATUS,   16#2).	      %% nameserver status query
%% -define(xxx,   16#3)  %% 16#3 reserved
%%  non standard
-define(UPDATEA,  16#9).	       %% add resource record
-define(UPDATED,  16#a).	       %% delete a specific resource record
-define(UPDATEDA, 16#b).	       %% delete all nemed resource record
-define(UPDATEM,  16#c).	       %% modify a specific resource record
-define(UPDATEMA, 16#d).	       %% modify all named resource record

-define(ZONEINIT, 16#e).	       %% initial zone transfer
-define(ZONEREF,  16#f).	       %% incremental zone referesh


%%
%% Currently defined response codes
%%
-define(NOERROR,  0).		%% no error
-define(FORMERR,  1).		%% format error
-define(SERVFAIL, 2).		%% server failure
-define(NXDOMAIN, 3).		%% non existent domain
-define(NOTIMP,	  4).		%% not implemented
-define(REFUSED,  5).		%% query refused
%%	non standard
-define(NOCHANGE, 16#f).		%% update failed to change db
-define(BADVERS,  16).

%%
%% Type values for resources and queries
%%
-define(T_A,		1).		%% host address
-define(T_NS,		2).		%% authoritative server
-define(T_MD,		3).		%% mail destination
-define(T_MF,		4).		%% mail forwarder
-define(T_CNAME,	5).		%% connonical name
-define(T_SOA,		6).		%% start of authority zone
-define(T_MB,		7).		%% mailbox domain name
-define(T_MG,		8).		%% mail group member
-define(T_MR,		9).		%% mail rename name
-define(T_NULL,		10).		%% null resource record
-define(T_WKS,		11).		%% well known service
-define(T_PTR,		12).		%% domain name pointer
-define(T_HINFO,	13).		%% host information
-define(T_MINFO,	14).		%% mailbox information
-define(T_MX,		15).		%% mail routing information
-define(T_TXT,		16).		%% text strings
-define(T_AAAA,         28).            %% ipv6 address
%% SRV (RFC 2052)
-define(T_SRV,          33).            %% services
%% NAPTR (RFC 2915)
-define(T_NAPTR,        35).            %% naming authority pointer
-define(T_OPT,          41).            %% EDNS pseudo-rr RFC2671(7)
%% SPF (RFC 4408)
-define(T_SPF,          99).            %% server policy framework
%%      non standard
-define(T_UINFO,	100).		%% user (finger) information
-define(T_UID,		101).		%% user ID
-define(T_GID,		102).		%% group ID
-define(T_UNSPEC,	103).		%% Unspecified format (binary data)
%%	Query type values which do not appear in resource records
-define(T_AXFR,		252).		%% transfer zone of authority
-define(T_MAILB,	253).		%% transfer mailbox records
-define(T_MAILA,	254).		%% transfer mail agent records
-define(T_ANY,		255).		%% wildcard match

%%
%% Symbolic Type values for resources and queries
%%
-define(S_A,		a).		%% host address
-define(S_NS,		ns).		%% authoritative server
-define(S_MD,		md).		%% mail destination
-define(S_MF,		mf).		%% mail forwarder
-define(S_CNAME,	cname).		%% connonical name
-define(S_SOA,		soa).		%% start of authority zone
-define(S_MB,		mb).		%% mailbox domain name
-define(S_MG,		mg).		%% mail group member
-define(S_MR,		mr).		%% mail rename name
-define(S_NULL,		null).		%% null resource record
-define(S_WKS,		wks).		%% well known service
-define(S_PTR,		ptr).		%% domain name pointer
-define(S_HINFO,	hinfo).		%% host information
-define(S_MINFO,	minfo).		%% mailbox information
-define(S_MX,		mx).		%% mail routing information
-define(S_TXT,		txt).		%% text strings
-define(S_AAAA,         aaaa).          %% ipv6 address
%% SRV (RFC 2052)
-define(S_SRV,          srv).           %% services
%% NAPTR (RFC 2915)
-define(S_NAPTR,        naptr).         %% naming authority pointer
-define(S_OPT,          opt).           %% EDNS pseudo-rr RFC2671(7)
%% SPF (RFC 4408)
-define(S_SPF,          spf).           %% server policy framework
%%      non standard
-define(S_UINFO,	uinfo).		%% user (finger) information
-define(S_UID,		uid).		%% user ID
-define(S_GID,		gid).		%% group ID
-define(S_UNSPEC,	unspec).        %% Unspecified format (binary data)
%%	Query type values which do not appear in resource records
-define(S_AXFR,		axfr).		%% transfer zone of authority
-define(S_MAILB,	mailb).		%% transfer mailbox records
-define(S_MAILA,	maila).		%% transfer mail agent records
-define(S_ANY,		any).		%% wildcard match

%%
%% Values for class field
%%

-define(C_IN,		1).      	%% the arpa internet
-define(C_CHAOS,	3).		%% for chaos net at MIT
-define(C_HS,		4).		%% for Hesiod name server at MIT
%%  Query class values which do not appear in resource records
-define(C_ANY,		255).		%% wildcard match


%% indirection mask for compressed domain names
-define(INDIR_MASK, 16#c0).

%%
%% Structure for query header, the order of the fields is machine and
%% compiler dependent, in our case, the bits within a byte are assignd
%% least significant first, while the order of transmition is most
%% significant first.  This requires a somewhat confusing rearrangement.
%%
-record(dns_header,
	{
	 id = 0,       %% ushort query identification number
	 %% byte F0
	 qr = 0,       %% :1   response flag
	 opcode = 0,   %% :4   purpose of message
	 aa = 0,       %% :1   authoritive answer
	 tc = 0,       %% :1   truncated message
	 rd = 0,       %% :1   recursion desired
	 %% byte F1
	 ra = 0,       %% :1   recursion available
	 pr = 0,       %% :1   primary server required (non standard)
	               %% :2   unused bits
	 rcode = 0     %% :4   response code
	}).

%% DNS resource record
-record(dns_rr,
	{
	 domain = "",   %% resource domain
	 type = any,    %% resource type
	 class = in,    %% reource class
	 cnt = 0,       %% access count
	 ttl = 0,       %% time to live
	 data = [],     %% raw data
	  %%
	 tm,            %% creation time
         bm = [],       %% Bitmap storing domain character case information.
         func = false   %% Optional function calculating the data field.
	}).

-define(DNS_UDP_PAYLOAD_SIZE, 1280).

-record(dns_rr_opt,           %% EDNS RR OPT (RFC2671), dns_rr{type=opt}
	{
	  domain = "",        %% should be the root domain
	  type = opt,
	  udp_payload_size = ?DNS_UDP_PAYLOAD_SIZE, %% RFC2671(4.5 CLASS)
	  ext_rcode = 0,      %% RFC2671(4.6 EXTENDED-RCODE)
	  version = 0,        %% RFC2671(4.6 VERSION)
	  z = 0,              %% RFC2671(4.6 Z)
	  data = []           %% RFC2671(4.4)
	 }).

-record(dns_query,
	{
	 domain,    %% query domain
	 type,      %% query type
	 class      %% query class
	 }).

-record(dns_rec,
	{
	  header :: #dns_header{},
	  qdlist = [] :: [#dns_query{}],
	  anlist = [] :: [#dns_rr{}],  %% list of answer entries
	  nslist = [] :: [#dns_rr{}],  %% list of authority entries
	  arlist = [] :: [#dns_rr{}]   %% list of resource entries
	}).

-endif.
