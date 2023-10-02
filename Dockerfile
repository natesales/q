FROM alpine:latest
COPY q /usr/bin/q
ENTRYPOINT ["/usr/bin/q"]
