FROM alpine:3.13

RUN apk add --no-cache bash curl git

ENTRYPOINT ["trivy-db-to"]
CMD [ "-h" ]

COPY trivy-db-to_*.apk /tmp/
RUN apk add --allow-untrusted /tmp/trivy-db-to_*.apk
