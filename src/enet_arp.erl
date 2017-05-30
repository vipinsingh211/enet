%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ARP packet codec
%% @end
%%%-------------------------------------------------------------------
-module(enet_arp).

%% API
-export([decode/2, decode_to_maps/2, encode/2]).

-include("enet_types.hrl").

%%====================================================================
%% API
%%====================================================================

decode(Pkt = <<HType:16/big, PType:16/big,
	 HAddrLen:8, PAddrLen:8,
        Oper:16/big,
        SndrHAddr:HAddrLen/binary,
        SndrPAddr:PAddrLen/binary,
        TargHAddr:HAddrLen/binary,
        TargPAddr:PAddrLen/binary,
	Padding/binary>>, _DecodeOpts) ->
    H = decode_htype(HType), P = decode_ptype(PType),
    if Padding =/= <<>>, (byte_size(Pkt)-byte_size(Padding)) > 32 -> 
	    %% do not report padding
	    io:format("arp got junk: ~w\n", [Padding]);
       true -> ok
    end,
    #arp{htype=H, ptype=P,
         haddrlen=HAddrLen, paddrlen=PAddrLen,
         op=decode_op(Oper),
         sender={(enet_codec:module(H)):decode_addr(SndrHAddr),
                 (enet_codec:module(P)):decode_addr(SndrPAddr)},
         target={(enet_codec:module(H)):decode_addr(TargHAddr),
                 (enet_codec:module(P)):decode_addr(TargPAddr)}};
decode(_Packet, _DecodeOpts) ->
    {error, bad_packet}.

decode_to_maps(Pkt = <<HType:16/big, PType:16/big,
	 HAddrLen:8, PAddrLen:8,
        Oper:16/big,
        SndrHAddr:HAddrLen/binary,
        SndrPAddr:PAddrLen/binary,
        TargHAddr:HAddrLen/binary,
        TargPAddr:PAddrLen/binary,
	Padding/binary>>, _DecodeOpts) ->
    H = decode_htype(HType), P = decode_ptype(PType),
    if Padding =/= <<>>, (byte_size(Pkt)-byte_size(Padding)) > 32 -> 
	    %% do not report padding
	    io:format("arp got junk: ~w\n", [Padding]);
       true -> ok
    end,
    #{arp=>#{htype=>H, ptype=>P,
         haddrlen=>HAddrLen, paddrlen=>PAddrLen,
         op=>decode_op(Oper),
         sender=>{(enet_codec:module(H)):decode_addr(SndrHAddr),
                 (enet_codec:module(P)):decode_addr(SndrPAddr)},
         target=>{(enet_codec:module(H)):decode_addr(TargHAddr),
                 (enet_codec:module(P)):decode_addr(TargPAddr)}}};
decode_to_maps(_Packet, _DecodeOpts) ->
    {error, bad_packet}.

encode(P = #arp{htype=ethernet,
                sender={SndrHAddr, SndrPAddr},
                target={TargHAddr, TargPAddr}}, EncodeOpts) ->
    encode(P#arp{htype=encode_htype(ethernet),
                 haddrlen=(enet_codec:module(ethernet)):addr_len(),
                 sender={(enet_codec:module(ethernet)):encode_addr(SndrHAddr), SndrPAddr},
                 target={(enet_codec:module(ethernet)):encode_addr(TargHAddr), TargPAddr}}, EncodeOpts);
encode(P = #arp{ptype=ipv4,
                sender={SndrHAddr, SndrPAddr},
                target={TargHAddr, TargPAddr}}, EncodeOpts) ->
    encode(P#arp{ptype=encode_ptype(ipv4),
                 paddrlen=(enet_codec:module(ipv4)):addr_len(),
                 sender={SndrHAddr, (enet_codec:module(ipv4)):encode_addr(SndrPAddr)},
                 target={TargHAddr, (enet_codec:module(ipv4)):encode_addr(TargPAddr)}}, EncodeOpts);

encode(#arp{htype=HType, ptype=PType,
            haddrlen=HAddrLen, paddrlen=PAddrLen,
            op=Oper,
            sender={SndrHAddr, SndrPAddr},
            target={TargHAddr, TargPAddr}}, _EncodeOpts)
  when is_integer(HType), is_integer(PType),
       byte_size(SndrHAddr) =:= byte_size(TargHAddr),
       byte_size(SndrHAddr) =:= HAddrLen,
       byte_size(SndrPAddr) =:= byte_size(TargPAddr),
       byte_size(SndrPAddr) =:= PAddrLen ->
    <<HType:16/big,
      PType:16/big,
      HAddrLen/big, PAddrLen/big,
      (encode_op(Oper)):16/big,
      SndrHAddr:HAddrLen/binary,
      SndrPAddr:PAddrLen/binary,
      TargHAddr:HAddrLen/binary,
      TargPAddr:PAddrLen/binary>>.

%%====================================================================
%% Internal functions
%%====================================================================

decode_op(1) -> request;
decode_op(2) -> reply.

encode_op(request) -> 1;
encode_op(reply) -> 2.

decode_htype(1) -> ethernet.
encode_htype(ethernet) -> 1.

decode_ptype(P) -> enet_eth:decode_type(P).
encode_ptype(P) -> enet_eth:encode_type(P).
    
