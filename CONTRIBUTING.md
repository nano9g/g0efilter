# Contributing

Thanks for helping improve g0efilter.

## Before You Start

For larger features or behavior changes, please open an issue or comment on an existing one first so the approach can be discussed. Small fixes, docs, and tests are welcome directly.

## AI Usage

AI tools are fine. Please understand, review, and test any AI-assisted changes yourself.

## Pull Requests

Keep PRs focused and use a conventional title when it fits:

```text
fix(scope): short description
```

Run the checks and tests that match the files you touched.

Go:

```sh
go mod tidy
go test -race -covermode=atomic -coverprofile=coverage.txt ./...
golangci-lint run --timeout=10m ./...
```

Action:

```sh
for f in action/*.js; do node --check "$f"; done
node --test 'action/*.test.js'
bash action/setup.test.sh
```

Docker/e2e:

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```
