# Licensing

IPMaster is Copyright (C) 2026 Murat Bulat and licensed under the **GNU General Public License version 3 only**
(SPDX identifier `GPL-3.0-only`). The licence text is the unmodified GNU GPLv3 in [`LICENSE`](../LICENSE)
(from https://www.gnu.org/licenses/gpl-3.0.txt, SHA-256 `3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986`).
"Only" means no later GPL version applies unless the copyright holder says so. If anything here seems to differ from
`LICENSE`, `LICENSE` is what counts; this page only summarises.

## Scope

- The licence covers the source in this repository from the commit that added `LICENSE`, and packages built from
  that source.
- Packages published before then (v0.8.0 and v0.9.0) were released before the licence was added (the v0.9.0 build
  script packaged only `README.md` with the executable; the v0.8.0 commit is not in the current history). Adding
  `LICENSE` to the repository does not change those archives or what was published with them.
- The copyright notice is kept in the README, this page, `THIRD-PARTY-NOTICES.md` and the assembly metadata
  (`Directory.Build.props`), not inside the GPL text. Source files carry no per-file headers; the root `LICENSE` covers
  the whole repository except the third-party files in `licenses/`.

## Distributing IPMaster

If you pass on IPMaster, modified or not, the GPLv3 applies to you. In short (the licence has the exact terms):

- Give recipients the GPLv3 text and keep the copyright, licence and no-warranty notices. Every release package already
  contains `LICENSE`, `THIRD-PARTY-NOTICES.md` and `licenses/`.
- Provide the **corresponding source** of the binaries you distribute (GPLv3 section 6): the source of that exact
  revision plus the scripts used to build and package it (`scripts/publish.ps1`, `scripts/installer/msi`). Each package
  has `SOURCE.txt` naming the commit it was built from, and the version reported by the assemblies ends in `+<commit>`.
  Linking to the matching tag or commit in this repository is the simplest way to meet that duty for unmodified
  packages; if you change the code, publish your changes with your binaries.
- Modified versions must say that they were changed, and when, and stay under the GPLv3.
- There is no warranty (sections 15 and 16).

## Third-party components

The packages bundle third-party libraries under their own licences (MIT, BSD-3-Clause, Apache-2.0, public domain; the
MSI also contains an MS-RL WiX custom action). They are listed with their copyright notices in
[`THIRD-PARTY-NOTICES.md`](../THIRD-PARTY-NOTICES.md); the full upstream notice files are in [`licenses/`](../licenses).
All bundled libraries are under licences that the FSF lists as compatible with GPLv3, with these points still open:

- **WiX custom action (MS-RL)**, MSI only: the FSF lists MS-RL as incompatible with the GPL. The custom action is a
  separate installer program that IPMaster does not link to (aggregation), and its source is public. Needs review by
  the maintainer before the next MSI release.
- **Adobe DNG SDK** licence inside the SkiaSharp native notices: not on the FSF list. Whether IPMaster's SkiaSharp build
  includes that code was not verified. Needs review.

When a dependency version changes, update the table in `THIRD-PARTY-NOTICES.md` and re-copy the notice files in
`licenses/` from the new packages.
