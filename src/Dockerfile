# Stage 1: Build the Golang Application
FROM golang:1.19 AS builder
WORKDIR /app

# Copy Go modules first to leverage caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application
RUN go build -o app .

# Stage 2: Create a lightweight production image
FROM scratch
WORKDIR /root/

# Copy the compiled binary from the builder stage
COPY --from=builder /app/app .

# Set environment variables (These can be overridden at runtime)
ENV PORT=8080

# Expose port for communication
EXPOSE 8080

# Run the application
CMD ["./app"]
