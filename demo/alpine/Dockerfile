FROM alpine:3 AS app

RUN apk add gcc musl-dev

COPY ./demo.c /

RUN gcc /demo.c -o /demo

CMD [ "sh", "-c", "while true; do sleep 30; done;" ]