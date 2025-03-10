# Use a base image with Nim installed
FROM debian:bullseye-slim

# Set working directory in container
WORKDIR /app

# Install any additional dependencies needed
RUN apt-get update && \
    apt-get install -y build-essential curl xz-utils git gcc-mingw-w64 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set Nim version via choosenim
ENV CHOOSENIM_CHOOSE_VERSION="2.0.0"
ENV PATH="/root/.nimble/bin:${PATH}"

# Install choosenim and Nim
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y

# Build using nimble shellcode
CMD nimble shellcode