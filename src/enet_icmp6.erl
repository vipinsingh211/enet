%%% @author Tony Rogvall <tony@rogvall.se>
%%% @copyright (C) 2014, Tony Rogvall
%%% @doc
%%%     ICMP6 encode/decode
%%% @end
%%% Created : 31 Jul 2014 by Tony Rogvall <tony@rogvall.se>

-module(enet_icmp6).

%% API
-export([decode/2
         ,decode_to_maps/2
         ,encode/1
         ,encode/2
         ,expand/1
        ]).

-include("../include/enet_types.hrl").

decode(Pkt = <<Type, Code, Checksum:16/big,
	       ID:16/big, Sequence:16/big,
	       Data/binary>>, [IPH=#ip_pseudo_hdr{}|_DecodeOpts]) ->
    IcmpType = decode_type(Type, Code),
    
    Pkt1 = <<(IPH#ip_pseudo_hdr.src)/binary,
	     (IPH#ip_pseudo_hdr.dst)/binary,
	     (IPH#ip_pseudo_hdr.length):32,
	     0:24, (IPH#ip_pseudo_hdr.proto),
	     Pkt/binary>>,
    #icmp6 {type=IcmpType,
	    csum=enet_checksum:oc16_check(Pkt1, Checksum),
	    id=ID,seq=Sequence,
	    data=Data}.

decode_to_maps(Pkt = <<Type, Code, Checksum:16/big,
	       ID:16/big, Sequence:16/big,
	       Data/binary>>, [IPH=#ip_pseudo_hdr{}|_DecodeOpts]) ->
    IcmpType = decode_type(Type, Code),
    
    Pkt1 = <<(IPH#ip_pseudo_hdr.src)/binary,
	     (IPH#ip_pseudo_hdr.dst)/binary,
	     (IPH#ip_pseudo_hdr.length):32,
	     0:24, (IPH#ip_pseudo_hdr.proto),
	     Pkt/binary>>,
    #{icmp6 =>#{type=>IcmpType,
	    csum=>enet_checksum:oc16_check(Pkt1, Checksum),
	    id=>ID,seq=>Sequence,
	    data=>Data}}.


expand(Pkt = #icmp6{type=Type}) when is_atom(Type) ->
    expand(Pkt#icmp6{type=encode_type(Type)});
expand(Pkt = #icmp6{type={Type, Code}
                   ,csum=Checksum
                   ,id=ID
                   ,seq=Sequence
                   ,data=Data})
  when not is_integer(Checksum),
       is_integer(Type), is_integer(Code),
       is_integer(ID), is_integer(Sequence),
       is_binary(Data) ->
    CSumPkt = <<Type, Code, 0:16/big,
               ID:16/big, Sequence:16/big,
               Data/binary>>,
    expand(Pkt#icmp6{csum=enet_checksum:oc16_sum(CSumPkt)});
expand(Pkt = #icmp6{type={Type, Code}
                   ,csum=Checksum
                   ,id=ID
                   ,seq=Sequence
                   ,data=Data})
  when is_integer(Type), is_integer(Code),
       is_integer(Checksum),
       is_integer(ID), is_integer(Sequence),
       is_binary(Data) ->
    Pkt.

encode(Pkt, _PsuedoHdr) ->
    encode(expand(Pkt)).

encode(#icmp6{type={Type, Code}
             ,csum=Checksum
             ,id=ID
             ,seq=Sequence
             ,data=Data}) when is_integer(Type), is_integer(Code),
                               is_integer(ID), is_integer(Sequence),
                               is_binary(Data) ->
    <<Type, Code, Checksum:16/big,
     ID:16/big, Sequence:16/big,
     Data/binary>>;
encode(Pkt) ->
    encode(expand(Pkt)).

%%====================================================================
%% Internal functions
%%====================================================================


decode_type(1, 0) -> unreach_net;
decode_type(1, 1) -> unreach_prohib;
decode_type(1, 2) -> unreach_scope;
decode_type(1, 3) -> unreach_host;
decode_type(1, 4) -> unreach_port;
decode_type(1, 5) -> unreach_source;
decode_type(1, 6) -> unreach_reject;

decode_type(2, _C) -> packet_to_big;

decode_type(3, 0) -> hop_limit_exceeded;
decode_type(3, 1) -> fragment_time_exceeded;
decode_type(3, C) -> {time_exceeded,C};

decode_type(4, C) -> {parameter_problem,C};

decode_type(100, C) -> {private_100,C};
decode_type(101, C) -> {private_101,C};

decode_type(128, 0) -> echo_request;
decode_type(129, 0) -> echo_reply;

decode_type(135, 0) -> neighbor_solicitation;
decode_type(136, 0) -> neighbor_advertisment;
decode_type(137, 0) -> redirect_message;
decode_type(138, 0) -> router_renumbering_command;
decode_type(138, 1) -> router_renumbering_result;
decode_type(138, 255) -> router_renumbering_sequence_number_reset;

decode_type(200, C) -> {private_200,C};
decode_type(201, C) -> {private_201,C};
%% add more...
decode_type(Type, Code) -> {Type, Code}.

encode_type(echo_request) -> {128, 0};
encode_type(echo_reply) -> {129, 0}.


