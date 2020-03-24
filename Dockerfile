FROM alpine

RUN apk add --update ca-certificates

WORKDIR /src/auth-api

COPY bin/microservices-demo-auth-api /usr/bin/auth-api

EXPOSE 3020

CMD ["/bin/sh", "-l", "-c", "auth-api"]