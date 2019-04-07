-module(gpb_handler_tcp).
-author("dmitryditas").

-include_lib("kv_pb.hrl").
-include_lib("erlcloud/include/erlcloud_aws.hrl").
-include_lib("common.hrl").

-behaviour(gen_server).
-behavior(ranch_protocol).

-define(IV, "0000000000000000").

%% API
-export([
    start_link/4
]).

%% gen_server callbacks
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-record(state, {
    client,
    transport,
    conf,
    ref,
    ciphertextblob,
    bin = <<>>
}).

%%====================================================================
%% API
%%====================================================================
start_link(Ref, Socket, Transport, [Conf, CiphertextBlob]) ->
    gen_server:start_link(?MODULE, [Ref, Socket, Transport, Conf, CiphertextBlob], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================
init([Ref, Socket, Transport, Conf, CiphertextBlob]) ->
    
    process_flag(trap_exit, true),
    
    
    self() ! {init, Ref, Socket, Transport},
    {ok, #state{conf = Conf, ciphertextblob = CiphertextBlob}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({init, Ref, Socket, Transport}, State) ->
    ok = ranch:accept_ack(Ref),
    ok = Transport:setopts(Socket, [{active, true}, binary]), %% TODO: active true?
    State1 = State#state{client = Socket, transport = Transport, ref = Ref},
    
    lager:debug("CLIENT CONNECTED ~p", [Socket]),
    
    {noreply, State1};
handle_info({tcp, Port, BinMsg}, #state{bin = Bin, transport = Transport, conf = Conf, ciphertextblob = CTB} = State) when Port =:= State#state.client ->
    State1 = case catch kv_pb:decode_msg(<<Bin/binary, BinMsg/binary>>, req_envelope) of
        #req_envelope{type = Type} = Req ->
            Resp = execute(Type, Req, Conf, CTB),
            EncResp = kv_pb:encode_msg(Resp),
            Transport:send(Port, EncResp),
            State#state{bin = <<>>};
        {'EXIT', _Reason} ->
            State#state{bin = <<Bin/binary, BinMsg/binary>>}
    end,
    {noreply, State1};
handle_info({tcp_closed, Port}, State) when Port =:= State#state.client ->
    
    lager:debug("CLIENT DISCONNECTED"),
    
    {noreply, State};
handle_info(Info, State) ->
    
    lager:warning("UNKNOWN MESSAGE ~p", [Info]),
    
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(OldVsn, State, _Extra) ->
    
    lager:debug("UPGRADE from ~p", [OldVsn]),
    
    {ok, State}.

%%====================================================================
%% Internal functions
%%====================================================================
execute(get_request_t, #req_envelope{get_req = #get_request{key = Key}}, Conf, CTB) ->
    {ok, Table} = application:get_env(minitask, table),
    {ok, KeyField} = application:get_env(minitask, key_field),
    Resp = case erlcloud_ddb2:get_item(Table, {KeyField, binary_to_list(Key)}, [], Conf) of
        {ok,[{_,EncValue},{_,Key}|_]} ->
            
            %% Decrypt EncValue (encrypted value from DDB)
            {ok, [_, {_, PlaintextKey}|_]} = erlcloud_kms:decrypt(CTB, [], Conf),
            EncValList = binary:split(EncValue, ?DIV, [global]),
    
            ValList = decrypt(EncValList, aes_cbc, binary_to_list(PlaintextKey), ?IV),
            
            [H|T] = lists:reverse(ValList),
            ValList1 = lists:reverse([bin_helper:depad(H)|T]),
            %%==========================================
            
            #get_response{error = ok, req = #data{key = Key, value = ValList1}};
        {ok, []} ->
            #get_response{error = not_found};
        _ ->
            #get_response{error = internal}
    end,
    #req_envelope{type = 4, get_resp = Resp};
execute(set_request_t, #req_envelope{set_req = #set_request{req = #data{key = Key, value = Value}}}, Conf, CTB) ->
    {ok, Table} = application:get_env(minitask, table),
    {ok, KeyField} = application:get_env(minitask, key_field),
    {ok, ValField} = application:get_env(minitask, val_field),
    
    %% Encrypt Value
    {ok, [_, {_, PlaintextKey}|_]} = erlcloud_kms:decrypt(CTB, [], Conf),
    EncValue = case size(Value) > 128 of
                 true ->
                     ValList = bin_helper:divide(Value, 128),
                     encrypt(ValList, aes_cbc, binary_to_list(PlaintextKey), ?IV);
                 false ->
                     PadVal = bin_helper:pad(Value, 128),
                     crypto:block_encrypt(aes_cbc, binary_to_list(PlaintextKey), ?IV, PadVal)
             end,
    %%===============
    
    Resp = case erlcloud_ddb2:put_item(Table, [{KeyField, {s, Key}}, {ValField, {b, bin_helper:to_line(EncValue)}}], [], Conf) of
               {ok, []} ->
                   #set_response{error = ok};
               _ ->
                   #get_response{error = internal}
           end,
    #req_envelope{type = 2, set_resp = Resp}.

encrypt(List, Type, Key, Ivec) ->
    encrypt(List, Type, Key, Ivec, []).

encrypt([], _, _, _, Acc) ->
    lists:reverse(Acc);
encrypt([H|T], Type, Key, Ivec, Acc) ->
    encrypt(T, Type, Key, Ivec, [crypto:block_encrypt(Type, Key, Ivec, H)|Acc]).

decrypt(List, Type, Key, Ivec) ->
    decrypt(List, Type, Key, Ivec, []).

decrypt([], _, _, _, Acc) ->
    lists:reverse(Acc);
decrypt([<<>>|T], Type, Key, Ivec, Acc) ->
    decrypt(T, Type, Key, Ivec, Acc);
decrypt([H|T], Type, Key, Ivec, Acc) ->
    decrypt(T, Type, Key, Ivec, [crypto:block_decrypt(Type, Key, Ivec, H)|Acc]).