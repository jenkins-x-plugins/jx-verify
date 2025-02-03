FROM alpine:3.21

RUN apk add --update git

ENTRYPOINT ["jx-verify"]

COPY ./build/linux/jx-verify /usr/bin/jx-verify