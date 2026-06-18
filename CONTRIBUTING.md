# Contributing to CMS-Detector
We welcome and appreciate contributions to our CMS detector code repository. This project aims to improve website fingerprinting methods and increase the accuracy of the detection process.

## How to Contribute
There are several ways to contribute to our project:

## Reporting Issues
If you encounter any bugs, errors, or issues while using the CMS detector code, please report them in the issues tab. When creating an issue, please provide as much detail as possible about the problem you are experiencing and steps to reproduce it.

## Contributing Code
We welcome contributions to the codebase. If you have any improvements or new website fingerprinting methods to suggest, please feel free to submit a pull request with your changes. Make sure to include a clear description of the changes and the rationale behind them.

## Code Style
All Go code must be formatted with `gofmt`. Run it before committing:

```bash
gofmt -w .
```

CI (`.github/workflows/ci.yml`) runs `gofmt`, `go vet`, `go build`, and `go test` on every
pull request — unformatted code fails the build. Please also run `go vet ./...` and
`go test ./...` locally before opening a PR.

When adding new detections, prefer the `html` fingerprint type (CSS selectors against the
parsed DOM) over `string_contains` for anything matching real tags or attributes — it
avoids false positives from page text. See the README for the available fingerprint types
and a worked example.

## Commit Messages
This project uses [Conventional Commits](https://www.conventionalcommits.org/). Format
every commit subject as `<type>(<optional scope>): <description>`:

```
feat(fingerprints): add Kirby CMS detection
fix: cap response body size to prevent OOM
docs: document the html fingerprint type
```

Common types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`. Keep the subject
short (≤ 50 chars), imperative, and lowercase; add a body explaining the *why* when it
isn't obvious. Breaking changes use `!` (e.g. `feat!: ...`) or a `BREAKING CHANGE:` footer.

## Testing
We are always looking for contributors to help test and verify the accuracy of the website fingerprinting methods. If you are interested in helping with testing, please reach out to us.

## Code of Conduct
We expect all contributors to follow our code of conduct. This ensures that everyone is treated with respect and that our community remains a welcoming and inclusive place.

## Conclusion
We believe that with the help of our community, we can continue to improve website fingerprinting methods and increase the accuracy of the detection process. Thank you for considering contributing to our project!