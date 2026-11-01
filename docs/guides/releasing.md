# Releasing, packaging and the GitHub mirror

ADR 0006: development and the full CI run on the homelab GitLab; GitHub is a mirror that receives
the official releases (tags, PyPI wheels) and external pull requests. This guide covers the
version, the packages (CMake, vcpkg, wheels), the release steps and the external PR flow.

## Version

`project(openiec61850 VERSION x.y.z)` in the top-level `CMakeLists.txt` is the single source of
truth:

- the C++ library reports it through `openiec61850::version()` (`src/core/version.cpp.in`);
- the Python package gets it from scikit-build-core's regex provider
  (`[tool.scikit-build.metadata.version]` in `pyproject.toml`) and `openiec61850.__version__`
  from the native module;
- the CMake package version file (`openiec61850ConfigVersion.cmake`) is generated from it.

The vcpkg manifests (`vcpkg.json` and `packaging/vcpkg/openiec61850/vcpkg.json`) need a literal
version. `packaging/check_version.py` fails when they disagree with CMake; with `--tag vX.Y.Z` it
also checks the tag and that `CHANGELOG.md` has a `## [X.Y.Z] - YYYY-MM-DD` section. The release
jobs run it on GitLab and GitHub.

While the version is 0.x, minor releases may break the API: the CMake version file uses
`SameMinorVersion`, so `find_package(openiec61850 0.1)` does not accept 0.2.

## C++ package (CMake)

`cmake --install` installs the headers, the library, the tools and a relocatable CMake package:

```
include/openiec61850/...
lib/libopeniec61850.a
lib/cmake/openiec61850/openiec61850{Config,ConfigVersion,Targets,Targets-<config>}.cmake
bin/openiec61850-server, bin/openiec61850-client
```

```cmake
find_package(openiec61850 0.1 CONFIG REQUIRED)
target_link_libraries(app PRIVATE openiec61850::openiec61850)
```

- The config calls `find_dependency` for Asio (public headers), pugixml (static library only: it
  is a private dependency that reaches the final link) and OpenSSL 3 when the library was built
  with `OPENIEC61850_ENABLE_TLS`. Consumers get these from vcpkg or the system.
- Install rules are on by default when openiec61850 is the top-level project
  (`OPENIEC61850_INSTALL`); the Python build turns them off so the wheel carries only the module.
- Static is the default. `BUILD_SHARED_LIBS=ON` works on Linux and macOS (default symbol
  visibility, `SOVERSION` = major.minor). Windows DLLs would need export macros on every public
  class, so a shared build is rejected there; the cost is not worth it before the API settles.
- The CTest test `package.consumer` (label `package`, part of every `ctest` run with tests on)
  installs the build tree into `build/<preset>/package-test/prefix`, checks that no installed
  `.cmake` file points into the source tree, then builds `tests/package/` (a separate project:
  `find_package` + a program that serves an SCL model and reads it back over loopback) against
  that prefix and runs it.

### vcpkg overlay port

`packaging/vcpkg/openiec61850/` is a port that builds the checkout it lives in, so other vcpkg
projects can consume an unreleased tree:

```bash
vcpkg install openiec61850 --overlay-ports=/path/to/openiec61850/packaging/vcpkg
vcpkg install "openiec61850[tls,tools]" --overlay-ports=...
```

vcpkg's ABI hash does not see changes to the source tree, so rebuild with
`--binarysource=clear` (or `VCPKG_BINARY_SOURCES=clear`) after changing it. A port for the vcpkg
registry would replace the local `SOURCE_PATH` with `vcpkg_from_github` on the release tag (see
the comment in the portfile).

## Python wheels (cibuildwheel)

Configuration: `[tool.cibuildwheel]` in `pyproject.toml`. CPython 3.10 to 3.13, no musllinux,
no 32-bit.

- Linux: `manylinux_2_28` images (AlmaLinux 8, GCC toolset with C++20 coroutines).
  `before-all` runs `packaging/cibuildwheel/install-vcpkg.sh`, which installs the vcpkg
  prerequisites (zip, unzip, curl, tar, git, pkgconfig, perl, make, ninja) and clones vcpkg at the
  manifest's `builtin-baseline`. The vcpkg binary cache lives in the container, so the
  dependencies are built once per `cibuildwheel` run and reused for every CPython version.
  `VCPKG_FORCE_SYSTEM_BINARIES=1` makes vcpkg use the image's cmake and ninja (required on
  aarch64, harmless on x86_64). The repair step runs `auditwheel repair` and prints
  `auditwheel show`.
- macOS (arm64, `MACOSX_DEPLOYMENT_TARGET=11.0`) and Windows (AMD64, triplet
  `x64-windows-static-md` so no DLL needs bundling, vcpkg from the runner's
  `VCPKG_INSTALLATION_ROOT`): **configured but never run yet**. Expect to fix them on the first
  GitHub `release` workflow run (use `workflow_dispatch` for a dry run that publishes nothing).
- The test-only `openiec61850._testing` extension is never built
  (`OPENIEC61850_BUILD_PYTHON_TESTING=OFF`). The wheel `test-command` runs `tests/python`: the
  tests that need the fake server skip, the rest (import, types, values, server API without a
  fake peer) run against the installed wheel.

Local run (needs Docker):

```bash
pip install cibuildwheel
CIBW_BUILD=cp312-manylinux_x86_64 cibuildwheel --platform linux --output-dir wheelhouse
```

cibuildwheel copies the whole project directory into the container, `build/` included; run it
from a clean checkout (`git worktree add` or `git archive HEAD | tar -x -C /tmp/src`) when
`build/` is large.

### Validated so far

Run locally on 2026-10-25 with cibuildwheel 4.3.4 and Docker (WSL2 host), from a clean export
of the tree:

| Identifier | Result | Wheel |
|---|---|---|
| `cp312-manylinux_x86_64` | built, repaired, tested | `openiec61850-0.1.0-cp312-cp312-manylinux_2_28_x86_64.whl`, 1.8 MiB (`_core` 4.7 MiB uncompressed) |
| `cp313-manylinux_x86_64` | built, repaired, tested | `openiec61850-0.1.0-cp313-cp313-manylinux_2_28_x86_64.whl`, 1.8 MiB |

- Time: about 1.5 min for `before-all` (dnf + vcpkg clone/bootstrap), about 2 min for the
  vcpkg dependencies on the first CPython version, about 1 min per wheel after that (the second
  version restored the 4 vcpkg packages from the container's cache).
- `auditwheel show`: consistent with `manylinux_2_28_x86_64`; only libc, libm, libpthread,
  libgcc_s and libstdc++ are external, nothing is grafted (pugixml and Asio are static).
- Wheel contents: the pure-Python package, `_core*.so`, `_core.pyi`, `py.typed`, LICENSE and
  NOTICE. No `_testing`, headers, static library or CMake files.
- `test-command`: 43 passed, 42 skipped (those needing `_testing`). Every test that uses the
  fake server must get it through the `server` fixture or `pytest.importorskip(
  "openiec61850._testing")`; a bare `from openiec61850._testing import ...` fails the wheel tests.
- Not run: cp310, cp311, aarch64, macOS, Windows.

## Release steps

1. On GitLab `main`, in one merge request: set the new version in `CMakeLists.txt`, `vcpkg.json`
   and `packaging/vcpkg/openiec61850/vcpkg.json`; move the `[Unreleased]` entries of
   `CHANGELOG.md` under `## [X.Y.Z] - YYYY-MM-DD` and leave an empty `[Unreleased]`. Check with
   `python3 packaging/check_version.py --tag vX.Y.Z`.
2. After the merge (full pipeline green, interop included), tag `main` on GitLab:
   `git tag -a vX.Y.Z -m "openiec61850 X.Y.Z" && git push origin vX.Y.Z`.
3. GitLab tag pipeline: `package:sdist` (checks the version against the tag), `package:wheels`
   (Linux wheels, homelab runner with Docker) and `release:gitlab` (GitLab release linking both
   artifacts). These are the reference artifacts; nothing is uploaded to PyPI from GitLab.
4. The push mirror sends the tag to GitHub, which runs `.github/workflows/release.yml`: sdist
   (version check again), wheels for Linux x86_64/aarch64, macOS arm64 and Windows AMD64, then
   the `pypi` job (waits for the `pypi` environment approval) publishes with trusted publishing,
   and `github-release` creates the GitHub release with the CHANGELOG section and the files.
5. Verify: `pip install openiec61850==X.Y.Z` in a clean venv, `python -c "import openiec61850;
   print(openiec61850.__version__)"`.

A tag that fails on GitHub before the `pypi` job can be deleted and pushed again. Once PyPI has
the version it cannot be replaced: fix forward with X.Y.Z+1.

### One-time setup

- **GitLab push mirror** (Settings > Repository > Mirroring repositories): push to
  `https://github.com/vicentevendramin/openiec61850.git` with a fine-grained GitHub token limited to that
  repository (contents: read/write, workflows: read/write), stored only in GitLab. Mirror all
  branches and tags; "keep divergent refs" off.
- **GitHub**: protect `main` and `v*` tags so that only the mirror token can push; create the
  `pypi` environment with required reviewers and deployment restricted to `v*` tags.
- **PyPI**: add a trusted publisher for project `openiec61850` (owner/repository, workflow
  `release.yml`, environment `pypi`). Before the first upload, use a "pending publisher". No
  API token is stored anywhere.

## External pull requests

GitHub is never written to directly: `main` there only moves through the mirror. A PR opened on
GitHub goes through this flow:

1. **Public checks.** `.github/workflows/ci.yml` builds and tests the PR (C++ release build with
   `-Werror` and all CTest tests, Python tests with the fake server). Homelab jobs (interop,
   long fuzzing, Docker runners) never run for external code (ADR 0006). The PR template asks
   for the clean-room statement (ADR 0001) and Apache-2.0 licensing.
2. **Review on GitHub.** Discussion and change requests stay on the PR, so the contributor sees
   them. The maintainer reads the whole diff before any of it runs on the homelab.
3. **Import to GitLab.** Once approved:

   ```bash
   git fetch github pull/<N>/head:gh-pr-<N>
   git push origin gh-pr-<N>
   ```

   and open a GitLab merge request from `gh-pr-<N>` titled `GitHub #<N>: <title>`. The full
   pipeline runs there, interop included, on code that has already been reviewed.
4. **Merge on GitLab** keeping the contributor as the commit author (rebase or fast-forward; no
   squash that rewrites authorship, or add a `Co-authored-by:` trailer if squashing). Add
   `Closes vicentevendramin/openiec61850#<N>` to the merge commit or the last commit message.
5. **Mirror back.** The push mirror updates GitHub `main`. If the PR commits landed unchanged,
   GitHub marks the PR as merged; otherwise close it with a comment linking the commit.

If the homelab pipeline finds a problem the public CI missed, report it on the GitHub PR (with
the relevant log excerpt) and let the contributor update it; then import again.
