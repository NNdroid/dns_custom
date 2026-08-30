#!/bin/bash
set -e

echo "=== Running dns_custom Unit & E2E Tests ==="
go test -v -race ./...
echo "=== All Tests Passed! ==="
