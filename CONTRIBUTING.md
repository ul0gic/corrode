# Contributing to Corrode

Thank you for wanting to improve Corrode! To keep the project aligned with ul0gic's goals, please follow these guidelines:

1. **License Alignment**
   - All contributions are accepted under the project's MIT License.
   - By opening a pull request, you confirm you have the rights to the code and that it may be redistributed under that license.

2. **Attribution**
   - Preserve the copyright and license notices required by the MIT License.
   - Public credit to **ul0gic** and a link to the repository are appreciated.

3. **Reuse**
   - Commercial, private, and open-source use are permitted under the license terms.
   - Sharing useful improvements back with the community is encouraged.

4. **Pull Request Expectations**
   - Fetch the latest upstream `main` and merge or rebase it into your branch before opening a PR. If `main` moves, update the branch again and let the checks finish before merging.
   - Keep each PR scoped. For a test, identify a production failure it catches. Use a small fixture that exercises the real code when changing scanner behavior.
   - Describe any new detections, dependencies, or permissions.
   - The PR is the CI gate. A maintainer merges after lint, tests, the Linux and macOS builds, and the security audit pass. For a release, bump the package version in `Cargo.toml` and update `Cargo.lock` in the PR. Merging that PR authorizes publication. The release workflow builds the binaries, tags the merged commit as `v<version>`, creates the GitHub Release, and publishes to crates.io. Ordinary merges skip publication.

5. **Code of Conduct**
   - Be respectful, assume best intent, and focus on constructive feedback. Harassment or discriminatory language won’t be tolerated.

## Running tests

Run `cargo test --locked --workspace` before opening a PR. CI uses the same command.
Unit tests live alongside the Rust code they exercise. The component suite in
`tests/component/` tests public scanner behavior and CLI errors using synthetic
inputs in `tests/fixtures/`. Run one area with, for example,
`cargo test --locked --test component config::`.

The pages in `tests/manual/` are for optional browser checks. The automated suite
runs without Chrome.

Questions or thoughts? Open a GitHub issue or tag **@ul0gic**.
