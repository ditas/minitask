-module(bin_helper).
-author("dmitryditas").

-include_lib("common.hrl").

%% API
-export([
    divide/2,
    send_list/2,
    pad/2,
    depad/1,
    to_line/1
]).

divide(Bin, Len) ->
    lists:reverse(divide_rec(Bin, Len, [])).

divide_rec(Bin, Len, Acc) when byte_size(Bin) == Len ->
    [Bin|Acc];
divide_rec(Bin, Len, Acc) when byte_size(Bin) < Len ->
    [pad(Bin, Len)|Acc];
divide_rec(Bin, Len, Acc) ->
    <<Part:Len/binary, Rest/binary>> = Bin,
    divide_rec(Rest, Len, [Part|Acc]).

send_list(_, []) ->
    ok;
send_list(Sock, [H|T]) ->
    gen_tcp:send(Sock, H),
    send_list(Sock, T).

pad(Bin, Len) ->
    string:left(binary_to_list(Bin) ++ binary_to_list(?DIV), Len, $0).

depad(Bin) ->
    case binary:split(Bin, ?DIV) of
        [BinVal, _] ->
            binary_to_list(BinVal);
        BinVal ->
            binary_to_list(BinVal)
    end.

to_line(BinList) ->
    to_line(BinList, <<>>).

to_line([], Acc) ->
    Acc;
to_line([H|T], Acc) ->
    Div = ?DIV,
    to_line(T, <<Acc/binary, Div/binary, H/binary>>).