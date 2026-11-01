# Development on self-hosted GitLab, releases on GitHub

Development and CI run on a self-hosted GitLab in the maintainer's homelab, because that is where the containers, VMs and interoperability test servers are (libiec61850 servers, simulators). GitHub receives a mirror and the official releases (tags, wheels published to PyPI). The CI definition is GitLab's (`.gitlab-ci.yml`), and GitHub Actions, if any, is limited to what must run on the public side, such as publishing and checks on external PRs.

## Consequences

- External contributions arrive as PRs on GitHub and must be brought to GitLab. This synchronisation flow must be defined before accepting the first external PR.
- Jobs that depend on homelab infrastructure (interoperability tests, long fuzzing) do not run for external contributors.
