FROM ubuntu:24.04 AS app

FROM pwn.red/jail
COPY --from=app / /srv
COPY ./demo /srv/app/run

ENV JAIL_TIME=0