%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc IPv6 frame codec 
%% @end
%%%-------------------------------------------------------------------
-module(enet_ipv6).

%% API
-export([decode/2, decode_to_maps/2,
         decode_addr/1, encode_addr/1,
         addr_len/0]).

-export([payload/1, payload_type/1]).

-include("../include/enet_types.hrl").

%%====================================================================
%% API
%%====================================================================

decode(<<6:4, % version
         TrafficClass:8,
         FlowLabel:20/bits,
         PayloadLength:16/big,
         NextHdr:8,
         HopCount:8,
         Src:16/binary,
         Dest:16/binary,
         Payload:PayloadLength/binary>>, Options) ->
    Proto = enet_ipv4:decode_protocol(NextHdr),
    PseudoHdr = #ip_pseudo_hdr{proto=NextHdr,length=PayloadLength,
			       src=Src,dst=Dest},
    #ipv6{src=decode_addr(Src),dst=decode_addr(Dest),
          traffic_class=TrafficClass, flow_label=FlowLabel,
          payload_len = PayloadLength, hop_count=HopCount,
          next_hdr=Proto,
          payload=decode_payload(NextHdr, Payload, [], [PseudoHdr | Options])};
decode(_Frame, _) ->
    {error, bad_packet}.

decode_to_maps(<<6:4, % version
         TrafficClass:8,
         FlowLabel:20/bits,
         PayloadLength:16/big,
         NextHdr:8,
         HopCount:8,
         Src:16/binary,
         Dest:16/binary,
         Payload:PayloadLength/binary>>, Options) ->
    Proto = enet_ipv4:decode_protocol(NextHdr),
    PseudoHdr = #{ip_pseudo_hdr=>#{proto=>NextHdr,length=>PayloadLength,
			       src=>Src,dst=>Dest}},
    #{ipv6=>#{src=>decode_addr(Src),dst=>decode_addr(Dest),
          traffic_class=>TrafficClass, flow_label=>FlowLabel,
          payload_len => PayloadLength, hop_count=>HopCount,
          next_hdr=>Proto,
          payload=>decode_payload(NextHdr, Payload, [], [PseudoHdr | Options])}};
decode_to_maps(_Frame, _) ->
    {error, bad_packet}.

payload_type(#ipv6{next_hdr=P}) -> P.
payload(#ipv6{payload=D}) -> D.


%%====================================================================
%% Internal functions
%%====================================================================

decode_addr(B) -> list_to_tuple([X || <<X:16>> <= B ]).

encode_addr(localhost) -> <<1:128/big>>;
encode_addr({A,B,C,D,E,F,G,H}) ->
    <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>;
encode_addr(B) when is_binary(B), byte_size(B) =:= 16 -> 
    B.

addr_len() -> 16.

%decode_headers(Type, Data, Acc)

decode_payload(Code, Data, Acc, Options) ->
    Type = enet_ipv4:decode_protocol(Code),
    case extension_header(Type) of
        not_an_extension_header ->
            IPH = #ip_pseudo_hdr{} = lists:keyfind(ip_pseudo_hdr, 1, Options),
            Acc ++ [enet_codec:decode(Type, Data, 
                                      [IPH#ip_pseudo_hdr{proto=Code} |
                                       lists:delete(IPH,Options)])];
        variable ->
            <<NextHdr:8, HdrLen:8,
              HdrData:HdrLen/binary,
              Remaining/binary>> = Data,
            Extension = decode_header(Type, HdrData),
            decode_payload(NextHdr, Remaining, Acc ++ [Extension], Options);
        HdrLen ->
            <<HdrData:HdrLen/binary, Remaining/binary>> = Data,
            <<NextHdr:8, _:8, Header/binary>> = HdrData,
            Extension = decode_header(Type, Header),
            decode_payload(NextHdr, Remaining, Acc ++ [Extension], Options)
    end.

decode_header(ipv6_frag, <<Offset:13, _Res:2, M:1, ID:32/big>>) ->
    #ipv6_frag{offset=Offset,m=M,id=ID};
decode_header(ipv6_route, <<Type:8, SegmentsLeft:8, _:32, Addresses/binary>>) ->
    #ipv6_route{type=Type, segments=SegmentsLeft, addresses=Addresses};
decode_header(Type, Data) -> {Type, Data}.


extension_header(ip) -> variable;
extension_header(ipv6_route) -> variable;
extension_header(ipv6_frag) -> 8;
extension_header(esp) -> variable;
extension_header(ah) -> variable;
extension_header(ipv6_opts) -> variable;
extension_header(_) -> not_an_extension_header.
