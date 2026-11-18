# Contributing

Concord does not accept pull requests.

Report bugs, differences from mihomo and feature requests through the GitHub issue forms. Read this before opening
one:

- Reproduce the problem on the latest release or the current `main`, with the standalone `concord run`. A problem in
  the screens or features of an app that embeds Concord belongs in that app's repository.
- Concord follows mihomo. A bug report gives what the same configuration does under mihomo, with its version; a
  difference from mihomo that `docs/compatibility.md` lists is deliberate.
- A feature request links the implementation or documentation in mihomo or sing-box and stays within the scope of
  `docs/compatibility.md`.
- Give a minimal configuration with servers, passwords, UUIDs, keys and subscription URLs removed, and a log taken
  with `log-level: debug`.
- There is no usage support; see `docs/usage.md`.

An issue opened outside the forms, or left incomplete, is labelled `needs-info` and closed if it is still incomplete
7 days later. Closed issues are locked after 30 days.

Report security problems privately as described in [SECURITY.md](SECURITY.md), not in an issue.
