# Documentation

This directory contains the documentation for the Basic Security Audit Tool. The documentation is built using [MkDocs](https://www.mkdocs.org/) with the [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) theme.

## Building the Documentation

1. Install the documentation dependencies:
   ```bash
   pip install -r requirements-docs.txt
   ```

2. Serve the documentation locally:
   ```bash
   mkdocs serve
   ```

3. Build the documentation:
   ```bash
   mkdocs build
   ```

## Documentation Structure

```
docs/
├── assets/              # Static assets (images, etc.)
├── getting-started/     # Getting started guides
├── modules/            # Module documentation
│   ├── dns-security/   # DNS security module docs
│   └── ssl-security/   # SSL/TLS security module docs
├── standards/          # Standards documentation
├── development/        # Development guides
└── about/             # About pages
```

## Contributing to Documentation

1. All documentation is written in Markdown format
2. Follow the [Google Developer Documentation Style Guide](https://developers.google.com/style)
3. Include metadata in each page:
   ```yaml
   ---
   title: Page Title
   description: Page description for SEO
   ---
   ```

## SEO Guidelines

1. Use descriptive titles and headings
2. Include meta descriptions
3. Use proper heading hierarchy
4. Link related content
5. Include alt text for images

## Deployment

The documentation is automatically deployed to GitHub Pages when changes are pushed to the main branch. The deployment is handled by the GitHub Actions workflow in `.github/workflows/documentation.yml`.

## References

- [MkDocs Documentation](https://www.mkdocs.org/)
- [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)
- [Markdown Guide](https://www.markdownguide.org/) 