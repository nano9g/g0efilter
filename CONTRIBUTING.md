# Contributing

Thanks for helping improve g0efilter.

## Before You Start

For larger features, behavior changes, or changes that affect filtering behavior, please open an issue or comment on an existing one first so the approach can be discussed.

Small fixes, documentation updates, tests, and clearly scoped bug fixes are welcome directly.

## AI Usage

AI tools are fine. Please understand, review, and test any AI-assisted changes yourself before submitting them.

## Pull Requests

Keep PRs focused. Prefer smaller PRs that are easy to review over large mixed changes.

Use a conventional title when it fits:

```text
fix(scope): short description
```

Examples:

```text
fix(dns): handle empty resolver response
test(action): add setup coverage
docs(readme): clarify Docker usage
```

In your PR description, explain what changed, why it changed, and which checks you ran.

If you skipped a relevant check, or if a check failed for a known reason, explain that in the PR.

## Validation

Run the checks and tests that match the files you touched.

### Go

```sh
go mod tidy
go test -race -covermode=atomic -coverprofile=coverage.txt ./...
golangci-lint run --timeout=10m ./...
```

After running `go mod tidy`, make sure any changes to `go.mod` or `go.sum` are expected.

### Action

```sh
for f in action/*.js; do node --check "$f"; done
node --test 'action/*.test.js'
bash action/setup.test.sh
```

### Docker/e2e

```sh
FILTER_MODE=https scripts/e2e.sh
FILTER_MODE=dns scripts/e2e.sh
```

## Security

Please do not open a public issue for security vulnerabilities.

If the repository has a security policy, follow the instructions in `SECURITY.md`. Otherwise, contact the maintainers privately with enough detail to understand and reproduce the issue.
