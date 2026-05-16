# Multi-stage build for fleetsweeper. The final image is a distroless static
# runtime with the non-root user so it drops cleanly into PSS-baseline and
# restricted clusters.

FROM golang:1.26-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOFLAGS="-mod=readonly" go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/fleetsweeper .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/fleetsweeper /usr/local/bin/fleetsweeper
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/fleetsweeper"]
CMD ["serve", "--addr", ":8080"]
