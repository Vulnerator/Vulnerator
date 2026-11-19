# Contributing to Vulnerator 2.0

Bug reports, feature requests and pull requests are welcome.

## Report a problem or request a feature

Open an [issue](https://github.com/hbonesctr/Vulnerator/issues) and pick the template that fits. Search open and closed
issues first. Say what you did, what you expected and what happened, and include the Vulnerator version and a log
extract (Help > Error Reporting says where the log is).

**Never attach real scan results, checklists, eMASS exports or logs that still contain host names or IP addresses.**
Vulnerability data stays on the network it came from. Describe the problem or build a small synthetic sample instead.

## Code changes

There is no required local setup: every push is built and tested by GitHub Actions on Windows
([.github/workflows/build.yml](workflows/build.yml)).

1. Fork the repository and create a branch from `v2/net48` (for example `fix-cklb-import`).
2. Keep changes small and focused. The project targets .NET Framework 4.8 and uses the old-style
   `Vulnerator_v6.csproj`: add a `<Compile Include>` entry for each new .cs file and an `<EmbeddedResource>` entry for
   each new SQL file.
3. Add or extend a test in `tools/tests/` using synthetic data only.
4. Open a pull request against `v2/net48` and fill in the template. CI must pass.

Nothing in the program may contact the internet unless the user turns on a setting.
