# Contributing

Thank you for your interest in contributing to this project!

## Development

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Commit your changes using conventional commits
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

## Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/). Please format your commit messages as:

```
<type>: <description>

[optional body]
```

Examples:
- `feat: add user authentication`
- `fix: resolve memory leak in worker process`
- `docs: update API documentation`

## Changelog

The changelog is automatically generated using [git-cliff](https://git-cliff.org/). To update the changelog:

```bash
git-cliff --output CHANGELOG.md
```

The changelog follows the [Keep a Changelog](https://keepachangelog.com/) format and includes GitHub integration for PR links and contributor recognition.
