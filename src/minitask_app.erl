%%%-------------------------------------------------------------------
%% @doc minitask public API
%% @end
%%%-------------------------------------------------------------------

-module(minitask_app).

-behaviour(application).

-include_lib("kv_pb.hrl").

%% Application callbacks
-export([start/2, stop/1]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    {ok, Port} = application:get_env(minitask, port),
    
    {ok, Conf} = erlcloud_aws:profile(),
    Conf1 = erlcloud_aws:default_config_region(Conf, 'eu-west-1'),
    
    %% Creating CMK/data keys
    CiphertextBlob = initialize(Conf1),
    %%=======================
    
    {ok, _} = ranch:start_listener(
        gpb_ddb_service,
        32,
        ranch_tcp,
        [{port, Port}],
        gpb_handler_tcp,
        [Conf1, CiphertextBlob]
    ),
    ranch:set_max_connections(gpb_ddb_service, 100),
    
    lager:debug("STARTED ON PORT ~p", [Port]),
    
    minitask_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
initialize(Conf) ->
    {ok, [{_, CMK}]} = erlcloud_kms:create_key([], Conf),
    {_, KeyId} = lists:keyfind(<<"KeyId">>, 1, CMK),

    {ok, DataKey} = erlcloud_kms:generate_data_key(KeyId,[{key_spec, 'AES_128'}],Conf),
    
    [{_, CiphertextBlob}|_] = DataKey,
    CiphertextBlob.