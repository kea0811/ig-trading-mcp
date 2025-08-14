# Publishing to npm

## Prerequisites

1. **Create npm account** (if you don't have one):
   ```bash
   npm adduser
   ```
   Or sign up at: https://www.npmjs.com/signup

2. **Login to npm**:
   ```bash
   npm login
   ```

## Publishing Steps

### First Time Publishing

1. **Verify package details**:
   ```bash
   npm pack --dry-run
   ```
   This shows what files will be included in the package.

2. **Test locally** (optional):
   ```bash
   npm link
   # In another directory:
   npx ig-trading-mcp test
   ```

3. **Publish to npm**:
   ```bash
   npm publish
   ```

### Publishing Updates

1. **Update version** (follow semantic versioning):
   ```bash
   # For patches (bug fixes): 1.0.0 -> 1.0.1
   npm version patch

   # For minor updates (new features): 1.0.0 -> 1.1.0
   npm version minor

   # For major updates (breaking changes): 1.0.0 -> 2.0.0
   npm version major
   ```

2. **Publish the update**:
   ```bash
   npm publish
   ```

3. **Push tags to GitHub**:
   ```bash
   git push --tags
   ```

## Quick Commands

```bash
# One-line publish for patch update
npm version patch && npm publish && git push --tags

# Check package info after publishing
npm info ig-trading-mcp
```

## Testing After Publishing

Wait a few minutes for npm to propagate, then test:

```bash
# Test global installation
npm install -g ig-trading-mcp
ig-trading-mcp --version

# Test npx usage
npx ig-trading-mcp test
```

## Troubleshooting

### Authentication Error
```bash
npm login
```

### Package Name Taken
Check availability:
```bash
npm view ig-trading-mcp
```

### Permission Denied
Make sure you're logged in as the correct user:
```bash
npm whoami
```

### Files Missing in Package
Check `.npmignore` and ensure important files aren't excluded.

## npm Package Page

After publishing, your package will be available at:
https://www.npmjs.com/package/ig-trading-mcp

## Best Practices

1. **Always test before publishing**
2. **Update README with any API changes**
3. **Follow semantic versioning**
4. **Tag releases on GitHub**
5. **Keep dependencies up to date**

## Automating with GitHub Actions (Optional)

Create `.github/workflows/npm-publish.yml`:

```yaml
name: Publish to npm

on:
  release:
    types: [created]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm publish
        env:
          NODE_AUTH_TOKEN: ${{secrets.NPM_TOKEN}}
```

To use this:
1. Get npm token: `npm token create`
2. Add to GitHub secrets as `NPM_TOKEN`
3. Create releases on GitHub to trigger publishing