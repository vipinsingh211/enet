%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%     DHCP encode / decode for enet
%%% @end
%%% Created : 30 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(enet_dhcp).

-include("../include/enet_types.hrl").

%% API
-export([decode/2]).
-export([decode_to_maps/2]).
-export([encode/2]).


decode(<<Op, Htype, Hlen, Hops,  Xid:32, Secs:16, Flags:16,
	 Ciaddr:4/binary, Yiaddr:4/binary, Siaddr:4/binary, Giaddr:4/binary,
	 Chaddr:6/binary, _:10/binary, Sname:64/binary, File:128/binary,
	 Options/binary>>, _DecodeOpts) ->
    OptsList = case Options of
		   << ?DHCP_OPTIONS_COOKIE, Opts/binary>> ->
		       binary_to_options(Opts);
		   _ -> %% return empty list if the MAGIC is not there
		       []
	       end,
    #dhcp{op      = decode_op(Op),
	  htype   = Htype,
	  hlen    = Hlen,
	  hops    = Hops,
	  xid     = Xid,
	  secs    = Secs,
	  flags   = Flags,
	  ciaddr  = enet_ipv4:decode_addr(Ciaddr),
	  yiaddr  = enet_ipv4:decode_addr(Yiaddr),
	  siaddr  = enet_ipv4:decode_addr(Siaddr),
	  giaddr  = enet_ipv4:decode_addr(Giaddr),
	  chaddr  = enet_eth:decode_addr(Chaddr),
	  sname   = c_string(Sname),
	  file    = c_string(File),
	  options = OptsList}.

decode_to_maps(<<Op, Htype, Hlen, Hops,  Xid:32, Secs:16, Flags:16,
	 Ciaddr:4/binary, Yiaddr:4/binary, Siaddr:4/binary, Giaddr:4/binary,
	 Chaddr:6/binary, _:10/binary, Sname:64/binary, File:128/binary,
	 Options/binary>>, _DecodeOpts) ->
    OptsList = case Options of
		   << ?DHCP_OPTIONS_COOKIE, Opts/binary>> ->
		       binary_to_options(Opts);
		   _ -> %% return empty list if the MAGIC is not there
		       []
	       end,
    #{dhcp=>#{
      op      => decode_op(Op),
	  htype   => Htype,
	  hlen    => Hlen,
	  hops    => Hops,
	  xid     => Xid,
	  secs    => Secs,
	  flags   => Flags,
	  ciaddr  => enet_ipv4:decode_addr(Ciaddr),
	  yiaddr  => enet_ipv4:decode_addr(Yiaddr),
	  siaddr  => enet_ipv4:decode_addr(Siaddr),
	  giaddr  => enet_ipv4:decode_addr(Giaddr),
	  chaddr  => enet_eth:decode_addr(Chaddr),
	  sname   => c_string(Sname),
	  file    => c_string(File),
	  options => OptsList}}.

encode(D, _EncodeOpts) when is_record(D, dhcp) ->
    Op      = encode_op(D#dhcp.op),
    Htype   = D#dhcp.htype,
    Hlen    = D#dhcp.hlen,
    Hops    = D#dhcp.hops,
    Xid     = D#dhcp.xid,
    Secs    = D#dhcp.secs,
    Flags   = D#dhcp.flags,
    Ciaddr  = enet_ipv4:encode_addr(D#dhcp.ciaddr),
    Yiaddr  = enet_ipv4:encode_addr(D#dhcp.yiaddr),
    Siaddr  = enet_ipv4:encode_addr(D#dhcp.siaddr),
    Giaddr  = enet_ipv4:encode_addr(D#dhcp.giaddr),
    Chaddr  = pad(enet_eth:encode_addr(D#dhcp.chaddr), 16),
    Sname   = pad(list_to_binary(D#dhcp.sname), 64),
    File    = pad(list_to_binary(D#dhcp.file), 128),
    Opts    = options_to_binary(D#dhcp.options),
    <<Op, Htype, Hlen, Hops, Xid:32, Secs:16, Flags:16,
     Ciaddr/binary, Yiaddr/binary, Siaddr/binary, Giaddr/binary,
     Chaddr/binary, Sname/binary, File/binary, Opts/binary>>.


pad(X, Size) when is_binary(X) ->
    Len  = size(X),
    Plen = Size - Len,
    <<X/binary, 0:Plen/integer-unit:8>>.

c_string(Bin) ->
    [String, _Zeros] = binary:split(Bin, <<0>>),
    binary_to_list(String).


binary_to_options(Binary) ->
    binary_to_options(Binary, []).

binary_to_options(<<?DHO_END, _/binary>>, Acc) ->
    Acc;
binary_to_options(<<Tag, Rest/binary>>, Acc) ->
    TagName = decode_tag(Tag),
    Value = 
	case type(TagName) of
	    byte ->
		<<1, Byte, T/binary>> = Rest,
		Byte;
	    {enum,byte,Enums} ->
		<<1, Byte, T/binary>> = Rest,
		case lists:keyfind(Byte, 1, Enums) of
		    false -> 
			Byte;
		    {_,Enum} -> Enum
		end;
	    short ->
		<<2, Short:16, T/binary>> = Rest,
		Short;
	    shortlist ->
		<<N, Binary:N/binary, T/binary>> = Rest,
		[ H || <<H:16>> <= Binary];
	    integer ->
		<<4, Integer:32, T/binary>> = Rest,
		Integer;
	    string ->
		<<N, String:N/binary, T/binary>> = Rest,
		binary_to_list(String);
	    ip ->
		<<4, A, B, C, D, T/binary>> = Rest,
		{A, B, C, D};
	    iplist ->
		<<N, Binary:N/binary, T/binary>> = Rest,
		[ {A,B,C,D} || <<A,B,C,D>> <= Binary ];
	    vendor ->
		<<N, Binary:N/binary, T/binary>> = Rest,
		binary_to_options(Binary);
	    unknown ->
		<<N, Binary:N/binary, T/binary>> = Rest,
		Binary
	end,
    binary_to_options(T, [{TagName, Value} | Acc]).

options_to_binary(Options) ->
    options_to_binary(Options, []).

options_to_binary([{TagName,Value} | Options], Acc) ->
    Bin = option_to_binary(TagName, Value),
    options_to_binary(Options, [Bin | Acc]);
options_to_binary([], Acc) ->
    list_to_binary([?DHCP_OPTIONS_COOKIE | lists:reverse([?DHO_END|Acc])]).

option_to_binary(TagName, Val) ->
    Tag = encode_tag(TagName),
    case type(TagName) of
	byte  ->
	    <<Tag, 1, Val>>;
	{enum,byte,Enums} ->
	    case lists:keyfind(Val, 2, Enums) of
		false when is_integer(Val) -> 
		    <<Tag, 1, Val>>;
		{Val,_Enum} ->
		    <<Tag, 1, Val>>
	    end;
	short ->
	    <<Tag, 2, Val:16/big>>;
	shortlist ->
	    B = list_to_binary([<<S:16/big>> || S <- Val]),
	    <<Tag, (size(B)), B/binary>>;
	integer ->
	    <<Tag, 4, Val:32/big>>;
	string ->
	    B = list_to_binary(Val),
	    <<Tag, (size(B)), B/binary>>;
	ip ->
	    <<Tag, 4, (enet_ipv4:encode(Val))/binary>>;
	iplist ->
	    B = list_to_binary([enet_ipv4:encode(IP) || IP <- Val]),
	    <<Tag, (size(B)), B/binary>>;
	vendor ->
	    B = list_to_binary([<<T, (size(V)), V/binary>> || {T, V} <- Val]),
	    <<Tag, (size(B)), B/binary>>
    end.

decode_op(?BOOTREQUEST) -> request;
decode_op(?BOOTREPLY) -> reply;
decode_op(Op) -> Op.

encode_op(request) -> ?BOOTREQUEST;
encode_op(reply) -> ?BOOTREPLY;
encode_op(Op) -> Op.



%% decoding of option name
decode_tag(?DHO_SUBNET_MASK) -> subnet_mask;
decode_tag(?DHO_TIME_OFFSET) -> time_offset;
decode_tag(?DHO_ROUTERS) -> routers;
decode_tag(?DHO_TIME_SERVERS) -> time_servers;
decode_tag(?DHO_NAME_SERVERS) -> name_servers;
decode_tag(?DHO_DOMAIN_NAME_SERVERS) -> domain_name_servers;
decode_tag(?DHO_LOG_SERVERS) -> log_servers;
decode_tag(?DHO_COOKIE_SERVERS) -> cookie_servers;
decode_tag(?DHO_LPR_SERVERS) -> lpr_servers;
decode_tag(?DHO_IMPRESS_SERVERS) -> impress_servers;
decode_tag(?DHO_RESOURCE_LOCATION_SERVERS) -> resource_location_servers;
decode_tag(?DHO_HOST_NAME) -> host_name;
decode_tag(?DHO_BOOT_SIZE) -> boot_size;
decode_tag(?DHO_MERIT_DUMP) -> merit_dump;
decode_tag(?DHO_DOMAIN_NAME) -> domain_name;
decode_tag(?DHO_SWAP_SERVER) -> swap_server;
decode_tag(?DHO_ROOT_PATH) -> root_path;
decode_tag(?DHO_EXTENSIONS_PATH) -> extensions_path;
decode_tag(?DHO_IP_FORWARDING) -> ip_forwarding;
decode_tag(?DHO_NON_LOCAL_SOURCE_ROUTING) -> non_local_source_routing;
decode_tag(?DHO_POLICY_FILTER) -> policy_filter;
decode_tag(?DHO_MAX_DGRAM_REASSEMBLY) -> max_dgram_reassembly;
decode_tag(?DHO_DEFAULT_IP_TTL) -> default_ip_ttl;
decode_tag(?DHO_PATH_MTU_AGING_TIMEOUT) -> path_mtu_aging_timeout;
decode_tag(?DHO_PATH_MTU_PLATEAU_TABLE) -> path_mtu_plateau_table;
decode_tag(?DHO_INTERFACE_MTU) -> interface_mtu;
decode_tag(?DHO_ALL_SUBNETS_LOCAL) -> all_subnets_local;
decode_tag(?DHO_BROADCAST_ADDRESS) -> broadcast_address;
decode_tag(?DHO_PERFORM_MASK_DISCOVERY) -> perform_mask_discovery;
decode_tag(?DHO_MASK_SUPPLIER) -> mask_supplier;
decode_tag(?DHO_ROUTER_DISCOVERY) -> router_discovery;
decode_tag(?DHO_ROUTER_SOLICITATION_ADDRESS) -> router_solicitation_address;
decode_tag(?DHO_STATIC_ROUTES) -> static_routes;
decode_tag(?DHO_TRAILER_ENCAPSULATION) -> trailer_encapsulation;
decode_tag(?DHO_ARP_CACHE_TIMEOUT) -> arp_cache_timeout;
decode_tag(?DHO_IEEE802_3_ENCAPSULATION) -> ieee802_3_encapsulation;
decode_tag(?DHO_DEFAULT_TCP_TTL) -> default_tcp_ttl;
decode_tag(?DHO_TCP_KEEPALIVE_INTERVAL) -> tcp_keepalive_interval;
decode_tag(?DHO_TCP_KEEPALIVE_GARBAGE) -> tcp_keepalive_garbage;
decode_tag(?DHO_NIS_DOMAIN) -> nis_domain;
decode_tag(?DHO_NIS_SERVERS) -> nis_servers;
decode_tag(?DHO_NTP_SERVERS) -> ntp_servers;
decode_tag(?DHO_TFTP_SERVER_NAME) -> tftp_server_name;
decode_tag(?DHO_BOOTFILE_NAME) -> bootfile_name;
decode_tag(?DHO_VENDOR_ENCAPSULATED_OPTIONS) -> vendor_encapsulated_options;
decode_tag(?DHO_NETBIOS_NAME_SERVERS) -> netbios_name_servers;
decode_tag(?DHO_NETBIOS_DD_SERVERS) -> netbios_dd_servers;
decode_tag(?DHO_NETBIOS_NODE_TYPE) -> netbios_node_type;
decode_tag(?DHO_NETBIOS_SCOPE) -> netbios_scope;
decode_tag(?DHO_FONT_SERVERS) -> font_servers;
decode_tag(?DHO_X_DISPLAY_MANAGERS) -> x_display_managers;
decode_tag(?DHO_DHCP_REQUESTED_ADDRESS) -> dhcp_requested_address;
decode_tag(?DHO_DHCP_LEASE_TIME) -> dhcp_lease_time;
decode_tag(?DHO_DHCP_OPTION_OVERLOAD) -> dhcp_option_overload;
decode_tag(?DHO_DHCP_MESSAGE_TYPE) -> dhcp_message_type;
decode_tag(?DHO_DHCP_SERVER_IDENTIFIER) -> dhcp_server_identifier;
decode_tag(?DHO_DHCP_PARAMETER_REQUEST_LIST) -> dhcp_parameter_request_list;
decode_tag(?DHO_DHCP_MESSAGE) -> dhcp_message;
decode_tag(?DHO_DHCP_MAX_MESSAGE_SIZE) -> dhcp_max_message_size;
decode_tag(?DHO_DHCP_RENEWAL_TIME) -> dhcp_renewal_time;
decode_tag(?DHO_DHCP_REBINDING_TIME) -> dhcp_rebinding_time;
decode_tag(?DHO_VENDOR_CLASS_IDENTIFIER) -> vendor_class_identifier;
decode_tag(?DHO_DHCP_CLIENT_IDENTIFIER) -> dhcp_client_identifier;
decode_tag(?DHO_NWIP_DOMAIN_NAME) -> nwip_domain_name;
decode_tag(?DHO_NIS_PLUS_DOMAIN) -> nis_plus_domain;
decode_tag(?DHO_NIS_PLUS_SERVERS) -> nis_plus_servers;
decode_tag(?DHO_MOBILE_IP_HOME_AGENTS) -> mobile_ip_home_agents;
decode_tag(?DHO_SMTP_SERVERS) -> smtp_servers;
decode_tag(?DHO_POP3_SERVERS) -> pop3_servers;
decode_tag(?DHO_WWW_SERVERS) -> www_servers;
decode_tag(?DHO_FINGER_SERVERS) -> finger_servers;
decode_tag(?DHO_IRC_SERVERS) -> irc_servers;
decode_tag(?DHO_STREETTALK_SERVERS) -> streettalk_servers;
decode_tag(?DHO_STDA_SERVERS) -> stda_servers;
decode_tag(?DHO_USER_CLASS) -> user_class;
decode_tag(?DHO_FQDN) -> fqdn;
decode_tag(?DHO_DHCP_AGENT_OPTIONS) -> dhcp_agent_options;
decode_tag(?DHO_NDS_SERVERS) -> nds_servers;
decode_tag(?DHO_NDS_TREE_NAME) -> nds_tree_name;
decode_tag(?DHO_NDS_CONTEXT) -> nds_context;
decode_tag(?DHO_UAP) -> uap;
decode_tag(?DHO_AUTO_CONFIGURE) -> auto_configure;
decode_tag(?DHO_NAME_SERVICE_SEARCH) -> name_service_search;
decode_tag(?DHO_SUBNET_SELECTION) -> subnet_selection;
decode_tag(?DHO_TFTP_SERVER_ADDRESS) -> tftp_server_address;
decode_tag(Tag) -> Tag.


encode_tag(subnet_mask) -> ?DHO_SUBNET_MASK;
encode_tag(time_offset) -> ?DHO_TIME_OFFSET;
encode_tag(routers) -> ?DHO_ROUTERS;
encode_tag(time_servers) -> ?DHO_TIME_SERVERS;
encode_tag(name_servers) -> ?DHO_NAME_SERVERS;
encode_tag(domain_name_servers) -> ?DHO_DOMAIN_NAME_SERVERS;
encode_tag(log_servers) -> ?DHO_LOG_SERVERS;
encode_tag(cookie_servers) -> ?DHO_COOKIE_SERVERS;
encode_tag(lpr_servers) -> ?DHO_LPR_SERVERS;
encode_tag(impress_servers) -> ?DHO_IMPRESS_SERVERS;
encode_tag(resource_location_servers) -> ?DHO_RESOURCE_LOCATION_SERVERS;
encode_tag(host_name) -> ?DHO_HOST_NAME;
encode_tag(boot_size) -> ?DHO_BOOT_SIZE;
encode_tag(merit_dump) -> ?DHO_MERIT_DUMP;
encode_tag(domain_name) -> ?DHO_DOMAIN_NAME;
encode_tag(swap_server) -> ?DHO_SWAP_SERVER;
encode_tag(root_path) -> ?DHO_ROOT_PATH;
encode_tag(extensions_path) -> ?DHO_EXTENSIONS_PATH;
encode_tag(ip_forwarding) -> ?DHO_IP_FORWARDING;
encode_tag(non_local_source_routing) -> ?DHO_NON_LOCAL_SOURCE_ROUTING;
encode_tag(policy_filter) -> ?DHO_POLICY_FILTER;
encode_tag(max_dgram_reassembly) -> ?DHO_MAX_DGRAM_REASSEMBLY;
encode_tag(default_ip_ttl) -> ?DHO_DEFAULT_IP_TTL;
encode_tag(path_mtu_aging_timeout) -> ?DHO_PATH_MTU_AGING_TIMEOUT;
encode_tag(path_mtu_plateau_table) -> ?DHO_PATH_MTU_PLATEAU_TABLE;
encode_tag(interface_mtu) -> ?DHO_INTERFACE_MTU;
encode_tag(all_subnets_local) -> ?DHO_ALL_SUBNETS_LOCAL;
encode_tag(broadcast_address) -> ?DHO_BROADCAST_ADDRESS;
encode_tag(perform_mask_discovery) -> ?DHO_PERFORM_MASK_DISCOVERY;
encode_tag(mask_supplier) -> ?DHO_MASK_SUPPLIER;
encode_tag(router_discovery) -> ?DHO_ROUTER_DISCOVERY;
encode_tag(router_solicitation_address) -> ?DHO_ROUTER_SOLICITATION_ADDRESS;
encode_tag(static_routes) -> ?DHO_STATIC_ROUTES;
encode_tag(trailer_encapsulation) -> ?DHO_TRAILER_ENCAPSULATION;
encode_tag(arp_cache_timeout) -> ?DHO_ARP_CACHE_TIMEOUT;
encode_tag(ieee802_3_encapsulation) -> ?DHO_IEEE802_3_ENCAPSULATION;
encode_tag(default_tcp_ttl) -> ?DHO_DEFAULT_TCP_TTL;
encode_tag(tcp_keepalive_interval) -> ?DHO_TCP_KEEPALIVE_INTERVAL;
encode_tag(tcp_keepalive_garbage) -> ?DHO_TCP_KEEPALIVE_GARBAGE;
encode_tag(nis_domain) -> ?DHO_NIS_DOMAIN;
encode_tag(nis_servers) -> ?DHO_NIS_SERVERS;
encode_tag(ntp_servers) -> ?DHO_NTP_SERVERS;
encode_tag(tftp_server_name) -> ?DHO_TFTP_SERVER_NAME;
encode_tag(bootfile_name) -> ?DHO_BOOTFILE_NAME;
encode_tag(vendor_encapsulated_options) -> ?DHO_VENDOR_ENCAPSULATED_OPTIONS;
encode_tag(netbios_name_servers) -> ?DHO_NETBIOS_NAME_SERVERS;
encode_tag(netbios_dd_servers) -> ?DHO_NETBIOS_DD_SERVERS;
encode_tag(netbios_node_type) -> ?DHO_NETBIOS_NODE_TYPE;
encode_tag(netbios_scope) -> ?DHO_NETBIOS_SCOPE;
encode_tag(font_servers) -> ?DHO_FONT_SERVERS;
encode_tag(x_display_managers) -> ?DHO_X_DISPLAY_MANAGERS;
encode_tag(dhcp_requested_address) -> ?DHO_DHCP_REQUESTED_ADDRESS;
encode_tag(dhcp_lease_time) -> ?DHO_DHCP_LEASE_TIME;
encode_tag(dhcp_option_overload) -> ?DHO_DHCP_OPTION_OVERLOAD;
encode_tag(dhcp_message_type) -> ?DHO_DHCP_MESSAGE_TYPE;
encode_tag(dhcp_server_identifier) -> ?DHO_DHCP_SERVER_IDENTIFIER;
encode_tag(dhcp_parameter_request_list) -> ?DHO_DHCP_PARAMETER_REQUEST_LIST;
encode_tag(dhcp_message) -> ?DHO_DHCP_MESSAGE;
encode_tag(dhcp_max_message_size) -> ?DHO_DHCP_MAX_MESSAGE_SIZE;
encode_tag(dhcp_renewal_time) -> ?DHO_DHCP_RENEWAL_TIME;
encode_tag(dhcp_rebinding_time) -> ?DHO_DHCP_REBINDING_TIME;
encode_tag(vendor_class_identifier) -> ?DHO_VENDOR_CLASS_IDENTIFIER;
encode_tag(dhcp_client_identifier) -> ?DHO_DHCP_CLIENT_IDENTIFIER;
encode_tag(nwip_domain_name) -> ?DHO_NWIP_DOMAIN_NAME;
encode_tag(nis_plus_domain) -> ?DHO_NIS_PLUS_DOMAIN;
encode_tag(nis_plus_servers) -> ?DHO_NIS_PLUS_SERVERS;
encode_tag(mobile_ip_home_agents) -> ?DHO_MOBILE_IP_HOME_AGENTS;
encode_tag(smtp_servers) -> ?DHO_SMTP_SERVERS;
encode_tag(pop3_servers) -> ?DHO_POP3_SERVERS;
encode_tag(www_servers) -> ?DHO_WWW_SERVERS;
encode_tag(finger_servers) -> ?DHO_FINGER_SERVERS;
encode_tag(irc_servers) -> ?DHO_IRC_SERVERS;
encode_tag(streettalk_servers) -> ?DHO_STREETTALK_SERVERS;
encode_tag(stda_servers) -> ?DHO_STDA_SERVERS;
encode_tag(user_class) -> ?DHO_USER_CLASS;
encode_tag(fqdn) -> ?DHO_FQDN;
encode_tag(dhcp_agent_options) -> ?DHO_DHCP_AGENT_OPTIONS;
encode_tag(nds_servers) -> ?DHO_NDS_SERVERS;
encode_tag(nds_tree_name) -> ?DHO_NDS_TREE_NAME;
encode_tag(nds_context) -> ?DHO_NDS_CONTEXT;
encode_tag(uap) -> ?DHO_UAP;
encode_tag(auto_configure) -> ?DHO_AUTO_CONFIGURE;
encode_tag(name_service_search) -> ?DHO_NAME_SERVICE_SEARCH;
encode_tag(subnet_selection) -> ?DHO_SUBNET_SELECTION;
encode_tag(tftp_server_address) -> ?DHO_TFTP_SERVER_ADDRESS;
encode_tag(Tag) when is_integer(Tag) -> Tag.

%%% DHCP Option types
type(subnet_mask)                 -> ip;
type(time_offset)                 -> integer;
type(routers)                     -> iplist;
type(time_servers)                -> iplist;
type(name_servers)                -> iplist;
type(domain_name_servers)         -> iplist;
type(log_servers)                 -> iplist;
type(cookie_servers)              -> iplist;
type(lpr_servers)                 -> iplist;
type(impress_servers)             -> iplist;
type(resource_location_servers)   -> iplist;
type(host_name)                   -> string;
type(boot_size)                   -> short;
type(merit_dump)                  -> string;
type(domain_name)                 -> string;
type(swap_server)                 -> ip;
type(root_path)                   -> string;
type(extensions_path)             -> string;
type(ip_forwarding)               -> byte;
type(non_local_source_routing)    -> byte;
type(policy_filter)               -> iplist;
type(max_dgram_reassembly)        -> short;
type(default_ip_ttl)              -> byte;
type(path_mtu_aging_timeout)      -> integer;
type(path_mtu_plateau_table)      -> integer;
type(interface_mtu)               -> short;
type(all_subnets_local)           -> byte;
type(broadcast_address)           -> ip;
type(perform_mask_discovery)      -> byte;
type(mask_supplier)               -> byte;
type(router_discovery)            -> byte;
type(router_solicitation_address) -> ip;
type(static_routes)               -> iplist;
type(trailer_encapsulation)       -> byte;
type(arp_cache_timeout)           -> integer;
type(ieee802_3_encapsulation)     -> byte;
type(default_tcp_ttl)             -> byte;
type(tcp_keepalive_interval)      -> integer;
type(tcp_keepalive_garbage)       -> byte;
type(nis_domain)                  -> string;
type(nis_servers)                 -> iplist;
type(ntp_servers)                 -> iplist;
type(tftp_server_name)            -> string;
type(bootfile_name)               -> string;
type(vendor_encapsulated_options) -> vendor;
type(netbios_name_servers)        -> iplist;
type(netbios_dd_servers)          -> iplist;
type(netbios_node_type)           -> byte;
type(netbios_scope)               -> string;
type(font_servers)                -> iplist;
type(x_display_managers)          -> iplist;
type(dhcp_requested_address)      -> ip;
type(dhcp_lease_time)             -> integer;
type(dhcp_option_overload)        -> byte;
type(dhcp_message_type)           -> 
    {enum,byte,[{?DHCPDiscover,discover},
		{?DHCPOffer,offer},
		{?DHCPRequest, request},
		{?DHCPDecline, decline},
		{?DHCPAck, ack},
		{?DHCPNak, nack},
		{?DHCPRelease, release},
		{?DHCPInform, inform}]};
type(dhcp_server_identifier)      -> ip;
type(dhcp_parameter_request_list) -> string;
type(dhcp_message)                -> string;
type(dhcp_max_message_size)       -> short;
type(dhcp_renewal_time)           -> integer;
type(dhcp_rebinding_time)         -> integer;
type(vendor_class_identifier)     -> string;
type(dhcp_client_identifier)      -> string;
type(nwip_domain_name)            -> string;
type(nis_plus_domain)             -> string;
type(nis_plus_servers)            -> iplist;
type(mobile_ip_home_agents)       -> iplist;
type(smtp_servers)                -> iplist;
type(pop3_servers)                -> iplist;
type(www_servers)                 -> iplist;
type(finger_servers)              -> iplist;
type(irc_servers)                 -> iplist;
type(streettalk_servers)          -> iplist;
type(stda_servers)                -> iplist;
type(user_class)                  -> string;
type(fqdn)                        -> string;
type(dhcp_agent_options)          -> string;
type(nds_servers)                 -> iplist;
type(nds_tree_name)               -> string;
type(nds_context)                 -> string;
type(uap)                         -> string;
type(auto_configure)              -> byte;
type(name_service_search)         -> shortlist;
type(subnet_selection)            -> ip;
type(tftp_server_address)         -> ip;
type(_)                           -> unknown.
