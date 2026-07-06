## What Does This PR Do?

## Contributing Guidelines

Have you read the [Contributing Guidelines](https://github.com/g0lab/g0efilter/blob/main/CONTRIBUTING.md)?

- [ ] I have read the contributing guidelines.
- [ ] For larger new features or behavior changes, I opened or commented on an issue, or this PR explains why that was not needed.

## Checks

Run the checks that match the files touched:

- [ ] Go changes: `go mod tidy`, `go test -race -covermode=atomic -coverprofile=coverage.txt ./...`, `golangci-lint run --timeout=10m ./...`
- [ ] Action changes: `for f in action/*.js; do node --check "$f"; done`, `node --test 'action/*.test.js'`, and `bash action/setup.test.sh`
- [ ] Filter, script, e2e, or `examples/build` changes: `FILTER_MODE=https scripts/e2e.sh` and `FILTER_MODE=dns scripts/e2e.sh`
