%%%-------------------------------------------------------------------
%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc ENet checksum routines.
%% @end
%%%-------------------------------------------------------------------
-module(enet_checksum).
-compile(native).

%% API
-export([oc16/1,oc16_sum/1,oc16_check/2]).

%% variants
-export([oc16_0/1,oc16_0_sum/1]).
-export([oc16_1/1,oc16_1_sum/1]).
-export([oc16_2/1,oc16_2_sum/1]).
%% benchmaek
-export([bench/2]).
-export([bench_loop_oc16_0/2]).
-export([bench_loop_oc16_1/2]).
-export([bench_loop_oc16_2/2]).

%% default 
-define(OC16, oc16_2).
-define(OC16_SUM, oc16_2_sum).
-define(OC16_CHECK, oc16_2_check).

%%====================================================================
%% API
%%====================================================================

oc16(Bin) when is_binary(Bin) -> ?OC16(Bin).
oc16_sum(Bin) when is_binary(Bin) -> ?OC16_SUM(Bin).
oc16_check(Bin,Sum) when is_binary(Bin) ->
    case ?OC16(Bin) of
        16#FFFF -> correct; %% -0
        _ -> {incorrect, Sum}
    end.	

%% fold 16-bit carry 
oc16_fold(Sum) when Sum > 16#ffff ->
    oc16_fold((Sum band 16#ffff) + (Sum bsr 16));
oc16_fold(Sum) ->
    Sum.

%% NOTE! fix bit compression missing last byte.
oc16_bytes(<<N:16,Bin/binary>>) -> [N | oc16_bytes(Bin)];
oc16_bytes(<<N:8>>) -> [N bsl 8];
oc16_bytes(<<>>) -> [].
    
%% version 0 with fixed last byte bug
oc16_0(Bin) -> lists:foldl(fun oc16_0/2, 0, oc16_bytes(Bin)).
oc16_0_sum(Bin) -> (bnot oc16_0(Bin)) band 16#FFFF.

%% 16 bits Ones complement addition.
oc16_0(A, Sum) ->
    case A + Sum of
        N when N > 16#FFFF ->
            Carry = N bsr 16,
            (N band 16#FFFF) + Carry;
        N when N =< 16#FFFF ->
            N
    end.


%% version 1 binary loop and fold after
oc16_1(Bin) when is_binary(Bin) -> oc16_1(Bin, 0).

oc16_1(<<A:16, Bin/binary>>, Sum) -> oc16_1(Bin, A+Sum);
oc16_1(<<A:8>>, Sum) -> oc16_fold((A bsl 8)+Sum);
oc16_1(<<>>, Sum) -> oc16_fold(Sum).
    
oc16_1_sum(Bin) -> (bnot oc16_1(Bin)) band 16#FFFF.


%% version 2 binary 
oc16_2(Bin) when is_binary(Bin) -> oc16_2(Bin,0).

oc16_2(<<A:16,B:16,Bin/binary>>,Sum) -> oc16_2(Bin,A+B+Sum);
oc16_2(<<A:16,B:8>>, Sum)  -> oc16_fold(A+(B bsl 8)+Sum);
oc16_2(<<A:16>>, Sum)  -> oc16_fold(A+Sum);
oc16_2(<<A:8>>, Sum) -> oc16_fold((A bsl 8)+Sum);
oc16_2(<<>>, Sum) -> oc16_fold(Sum).

oc16_2_sum(Bin) -> (bnot oc16_2(Bin)) band 16#FFFF.

%%
%% Benchmark variants to select the fastest.
%%

bench_packet() ->
    list_to_binary([16#E2,16#86|lists:duplicate(1483, 16#A5)]).

bench(oc16_0, N) ->
    Packet = bench_packet(),
    timer:tc(?MODULE, bench_loop_oc16_0, [N, Packet]);
bench(oc16_1, N) ->
    Packet = bench_packet(),
    timer:tc(?MODULE, bench_loop_oc16_1, [N, Packet]);
bench(oc16_2, N) ->
    Packet = bench_packet(),
    timer:tc(?MODULE, bench_loop_oc16_2, [N, Packet]).

bench_loop_oc16_0(0, _Packet) -> ok;
bench_loop_oc16_0(I, Packet) ->
    16#FFFF = oc16_0(Packet),
    bench_loop_oc16_0(I-1, Packet).

bench_loop_oc16_1(0, _Packet) -> ok;
bench_loop_oc16_1(I, Packet) ->
    16#FFFF = oc16_1(Packet),
    bench_loop_oc16_1(I-1, Packet).

bench_loop_oc16_2(0, _Packet) -> ok;
bench_loop_oc16_2(I, Packet) ->
    16#FFFF = oc16_2(Packet),
    bench_loop_oc16_2(I-1, Packet).
