FROM erlang:19-slim

#Copy the source folder into the Docker image
RUN mkdir /erlang_application
COPY . erlang_application/

RUN mkdir /root/.aws
COPY ./creds/config /root/.aws
COPY ./creds/credentials /root/.aws

RUN apt-get update \
    && apt-get install -y git

RUN cd erlang_application/ && \
    rm -Rf _build && \

    ./rebar3 upgrade && \
    ./rebar3 as prod tar && \

    ls -l && \

    tar -xf "_build/prod/rel/minitask/minitask-0.1.0.tar.gz"

ENV REPLACE_OS_VARS=true

ENTRYPOINT ["erlang_application/bin/minitask"]
CMD ["console"]