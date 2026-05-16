# CLI Release

## GitHub Remote

The standalone CLI repository is expected to use:

```sh
git remote add origin https://github.com/frankmanzhu/zmanager.git
```

The Homebrew tap should live in a separate repository named
`homebrew-zmanager`:

```sh
https://github.com/frankmanzhu/homebrew-zmanager.git
```

That naming lets users run `brew install frankmanzhu/zmanager/zm`.

## Release Checklist

1. Run:

   ```sh
   cargo test --workspace
   cargo clippy --workspace --all-targets
   cargo fmt --check
   ```

2. Tag the CLI repository:

   ```sh
   git tag v0.1.0
   git push origin main --tags
   ```

3. Update `Formula/zm.rb` if the release tag changed.

4. Copy `Formula/zm.rb` to the tap repository at `Formula/zm.rb`.

5. Validate the tap:

   ```sh
   brew audit --strict --formula Formula/zm.rb
   brew install --build-from-source Formula/zm.rb
   brew test zm
   ```

The formula builds from source and installs the `zm` binary with Cargo.
