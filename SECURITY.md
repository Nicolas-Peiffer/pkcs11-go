<!--
SPDX-FileCopyrightText: Copyright (c) 2026 The Eclipse Foundation and pkcs11-go Authors
SPDX-License-Identifier: MIT
-->

# Security Policy

pkcs11-go is the layer between Go programs and PKCS #11 modules: it marshals keys, PINs and
plaintext across the cgo boundary, and the projects built on it, such as
[crypto11](https://github.com/eclipse-keypont/crypto11), broker access to keys held in HSMs
through it. We take reports seriously and would rather hear about a suspected issue than not.

This project is an Eclipse Foundation project and adheres to the
[Eclipse Foundation Vulnerability Reporting Policy](https://www.eclipse.org/security/policy/).

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull
requests.**

Report privately through any of these channels:

- **[GitHub private vulnerability reporting](https://github.com/eclipse-keypont/pkcs11-go/security/advisories/new)**
  — preferred. It keeps the report, the fix and the advisory in one place.
- **The Eclipse Foundation Vulnerability Reporting Tracker**, by creating a
  [confidential issue](https://gitlab.eclipse.org/security/vulnerability-reports/-/issues/new?issuable_template=new_vulnerability).
  This is the Foundation-level channel and the right one if the issue spans several Eclipse KeyPont
  projects — a binding defect that crypto11 exposes, say.
- **The Eclipse Foundation security team**, at <security@eclipse-foundation.org>. See the
  [Eclipse Foundation Security Policy](https://www.eclipse.org/security/policy/) for the
  Foundation-level process. Use this channel if you would rather not report through GitHub or GitLab.

### What to include

The more of this you can supply, the faster we can confirm and fix:

- A description of the issue and why you believe it has security impact, including the type of
  issue (for example a buffer overflow, an out-of-bounds read, or a secret leak).
- The affected version or commit, and whether `main` is affected.
- The platform (OS, architecture, Go version) — `CK_ULONG` width and the loader differ between
  Unix and Windows.
- The PKCS #11 module involved (vendor, product, library version), if the issue depends on one.
- Step-by-step instructions to reproduce the issue, and the location of the affected source code
  (tag/branch/commit or direct URL), with full paths of the source files involved.
- Any configuration required to reproduce the issue, and related log files if you have them.
- A minimal reproducer. A small mock module that returns the values that trigger the bug is often
  the clearest one. Proof-of-concept or exploit code is welcome if you have it.
- Whether you intend to disclose publicly, and on what timeline.

Reports in any language are fine, and a partial report is better than none.

## What to expect

We will tell you when we have confirmed the issue, when a fix lands, and when the advisory is
published. If we conclude the report is not a vulnerability we will explain why, and you are
welcome to push back. This is a modest project; we do our best to respond promptly.

We work on a best-effort basis, but a strong security CI/CD pipeline backs every change: linting,
static analysis, vulnerability scanning and signed, provenance-attested releases. It reduces the
odds of a defect reaching a release, and it is why we would rather hear about a suspected issue
than not.

## Disclosure

We follow coordinated disclosure. We ask that you give us a reasonable opportunity to release a fix
before disclosing publicly — as a default, 90 days from acknowledgement, or until a fix is
released, whichever comes first. When a fix is released we publish a
[GitHub Security Advisory](https://github.com/eclipse-keypont/pkcs11-go/security/advisories),
with a CVE where one is warranted; for Eclipse projects CVEs are assigned through the Eclipse
Foundation security team. Reporters are credited by name unless they ask not to be.

## Supported versions

| Version  | Supported                                                         |
|----------|-------------------------------------------------------------------|
| `v1.2.x` | Yes — active development (release candidates until 1.2.0 ships)   |
| `v1.1.x` | Security fixes, until 1.2.0 is released                           |
| Older    | No                                                                |

Fixes land on `main` first and ship in the next tagged release.

## Scope

A PKCS #11 module is native code loaded into your process: it already runs with your process's
privileges, so a module that sets out to attack its host does not need a bug in this binding to do
it. What the binding promises is that it handles a module's answers defensively and handles your
secrets carefully.

**In scope:**

- Memory safety at the cgo boundary: out-of-bounds reads or writes, use-after-free or double free
  of C buffers, unchecked lengths or counts reported by a module, and allocations a module can
  make unbounded.
- Secrets — PINs, key material, plaintext — left in C or Go buffers the binding allocated, or
  leaking through errors and logs.
- Marshalling that silently changes what is asked of the token: the wrong parameter structure or
  width, a value truncated, a template attribute dropped or altered.
- Module loading: searching for a library somewhere other than the path given, or loading a
  different library than the one named.
- Secure-by-default behaviour of the `p11` package (key templates, mechanism policy) that does not
  hold where it is documented to.
- Supply-chain integrity of the release pipeline: the signed tags, SBOM and provenance.

**Out of scope:**

- Vulnerabilities in a PKCS #11 module or token itself. Report those to the vendor — though if the
  binding could defend against one, tell us.
- A module deliberately written to attack the process that loads it.
- Insecure use by the caller, such as weak mechanisms passed to `cryptoki` directly with no policy
  installed, or a PIN kept in a Go `string`. If our documentation encourages an insecure pattern,
  that *is* worth reporting.
- Test-only code and the throwaway tokens and PINs used by the test suites.
