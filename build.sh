#!/bin/bash

for ARCH in darwin_amd64 darwin_arm64 linux_386 linux_arm64 linux_arm; do
  case "$ARCH" in
    darwin_amd64)
      # For Intel-based MacBooks and other x86_64 machines
      export GOARCH=amd64
      export GOOS=darwin
      ;;
    darwin_arm64)
      # For Apple Silicon-based MacBooks and other arm64 machines
      export GOARCH=arm64
      export GOOS=darwin
      ;;
    linux_386)
      # For 32-bit machines
      export GOARCH=386
      export GOOS=linux
      ;;
    linux_arm64)
      # For other arm64 machines
      export GOARCH=arm64
      export GOOS=linux
      ;;
    linux_arm)
      # For other arm machines
      export GOARCH=arm
      export GOOS=linux
      ;;
    *)
      echo "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  echo "Building for $ARCH..."
  go build -ldflags="-w -s" -o zkbnb-setup-$ARCH
done
