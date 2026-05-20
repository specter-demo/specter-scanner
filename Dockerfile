FROM gcr.io/distroless/static-debian12:nonroot
COPY dist/specter-scanner-linux-amd64 /specter-scanner
ENTRYPOINT ["/specter-scanner"]
