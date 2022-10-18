FROM golang:1.18 as builder

WORKDIR /app

# Download necessary Go modules
COPY go.mod go.sum ./
RUN go mod download

# Build go binary from sources
COPY . ./
RUN make build


FROM scratch

COPY --from=builder /app/build/panos_exporter /

EXPOSE 9654
ENTRYPOINT ["/panos_exporter"]
