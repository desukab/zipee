# Mounting feasibility

An evidence-based assessment of whether Zipee can ship a genuine filesystem
mount, and which route if so. Every claim below carries its source. Claims I
could not verify are marked as such rather than asserted.

**Last verified:** 2026-10-15.

---

## Summary

| Route | Entitlement needed | Verdict |
|---|---|---|
| **Apple FSKit** | `com.apple.developer.fskit.fsmodule` — a **managed capability**, applied for via Apple's developer portal | Viable, **pending approval**. Not yet granted to this project. |
| **macFUSE FSKit backend** | None | Technically viable, but **licensing blocks commercial bundling**. |
| **macFUSE kext backend** | None (user approves in System Settings) | Works, but needs a kext; deprecated path. |
| **macFUSE.framework `MFMount.framework`** | None | The cleanest technical route, same licensing caveat. |

**Neither route has been implemented or executed.** Zipee currently ships in-app
browsing only. See [platform-limitations.md](platform-limitations.md).

---

## 1. What the macFUSE FSKit backend actually does

Verified from macFUSE's own wiki (`macfuse/macfuse/wiki/FUSE-Backends`,
last edited 2025-10-30) and README.

### Confirmed

- macFUSE supports **two backends**. The default is a **kernel (VFS) API**
  requiring a kernel extension. Selecting `-o backend=fskit` uses **FSKit**,
  which macFUSE describes as "a user-space API ... introduced in macOS 15.4".
- So the FSKit backend needs **no kernel extension**.
- macFUSE 5.2.0 (2026-04-09) release notes: *"Introduce a new open source API
  for mounting volumes using the FSKit backend. The new API enables fully
  sandboxed file systems, which was not previously possible."*
- macFUSE 5.4.0 (2026-09-07) release notes: *"Update the build process for the
  FSKit backend to use Xcode 27.0 (macOS 27 SDK)"* and *"Add support for the new
  macOS 27 FSKit volume operation APIs while retaining compatibility with
  earlier macOS releases."*
- The wiki's Getting Started page states: *"All official macFUSE releases are
  digitally signed and approved by Apple's Notary Service. This means macFUSE is
  compatible with Gatekeeper and System Integrity Protection."*

So my earlier correction was right on the **no kext** and **notarized** points.

### The FSKit backend's documented limitations

These matter more than the headline, and macFUSE publishes them plainly:

| Limitation (verbatim from the wiki) | Consequence for an archive mount |
|---|---|
| *"Using mount points outside of /Volumes is not supported by FSKit."** | **Irrelevant.** Archives mount in `/Volumes` by convention. |
| *"Files are always opened in read/write mode."* | **Significant.** A read-only archive mount would have to accept read-write opens and refuse writes itself. Workable, but it means the backend must defend every write path — precisely the surface Zipee does not want to expose. |
| *"The FUSE notification API is not supported, yet."* | **Minor.** Affects invalidation when the archive changes on disk. Zipee would need to re-check explicitly. |
| *"Context information (`fuse_context_t`) is not available."* | Minor. Zipee does not need per-caller identity. |
| *"Most mount options previously handled by the kernel are not implemented, yet."* | Minor. |
| *"I/O performance of FSKit volumes is not on par with volumes using the kernel extension backend."* | **Relevant.** Per-operation FSKit callbacks are comparatively expensive; Zipee already documents that a mounted archive must be read in full for Finder to show it. |

### Not verified

- Whether the FSKit backend exposes the *complete* operation set an archive
  needs (`lookup`, `read_dir`, `getattr`, `open`, `read`, `release`, `statfs`)
  with usable semantics. The wiki lists what is *missing*; it does not
  affirmatively confirm what is present and correct.
- Whether a macOS 15.4-era FSKit is enough, or whether modern features Zipee
  would want (such as resource-fork or extended-attribute support) need macOS 26.
- Actual measured I/O throughput for archive content. That needs a Mac.

---

## 2. Licensing — the decisive finding

**This is the finding that most changes the recommendation.**

From `LICENSE.txt` in `macfuse/macfuse` (fetched 2026-10-15), clause 4:

> *"Redistributions in binary form, bundled with commercial software, are not
> allowed without specific prior written permission. This includes the
> automated download or installation or both of the binary form in the context
> of commercial software."*

And from the wiki's Open Source Status page:

> *"Bundling or integrating macFUSE with commercial software requires a
> paid-for license. Please refer to the macFUSE license and contact Benjamin
> Fleischer regarding commercial licensing options."*

Additional licence facts from the same file:

- The core is BSD-3-Clause-like (Google/Fuse4X/Tuxera heritage).
- `fuse_kernel.h` is *"redistributed here under the BSD license."*
- `mount_macfuse` is under the **Apple Public Source License (APSL)**.
- The package *"contains the following open-source software that is available
  under the GNU Lesser General Public License: FUSE user space library."*
- Since 3.9 (May 2019) some components are closed source; the last fully open
  release is 3.8.3.

### What this means for Zipee

| Action | Allowed? |
|---|---|
| Ship Zipee and require users to install macFUSE separately from macfuse.io | **Apparently yes** — that is not bundling. Needs confirmation. |
| Bundle `libfuse.dylib` or `MFMount.framework` inside a commercial Zipee | **No**, without a paid licence. |
| Have Zipee automatically download and install macFUSE | **Explicitly prohibited** — the licence names "automated download or installation ... in the context of commercial software". |
| Link against a user-installed macFUSE at runtime | Unclear from the licence text; needs the author's answer. |

**Practical consequence:** if Zipee ships a mount, the mount is an *optional,
separately installed* feature, not part of the app. That is a materially
different product from Zipgeist's, where the mount is the product and the
installer handles everything.

**Not verified:** whether linking (as opposed to bundling) a user-installed
macFUSE is permitted, and at what cost. Only the licence holder can answer.
This is recorded as an open commercial question, not a solved one.

---

## 3. Apple's FSKit capability — applied for vs granted

These are different states, and conflating them would be the single easiest
way to mislead here.

**What is documented:**

- The entitlement `com.apple.developer.fskit.fsmodule` exists and is defined by
  Apple: *"An entitlement that indicates an extension provides an FSKit
  filesystem."* Its documented availability is **macOS 15.4.0 and later**.
- Entitlements of this kind are **managed capabilities**. Apple's Capability
  Requests documentation: *"Managed capabilities are app services that need an
  entitlement assigned to your account by Apple before you can enable them...
  click the Capability Requests tab... click the Request button... submit the
  request form."* It also notes the Account Holder submits for an organisation.

**The three states, stated precisely:**

| State | Meaning | Zipee's status |
|---|---|---|
| **Documented** | Apple publishes the entitlement and its availability | ✅ Verified |
| **Applied for** | A request has been submitted and is pending review | ❌ **Not done** |
| **Granted** | Apple has assigned the entitlement to the account | ❌ **Not done, not known** |

**Nothing in this repository asserts that Zipee holds this entitlement.** It
does not. Any build of Zipee today is unsigned-by-entitlement in this respect:
the app has no FSKit extension target and requests no such entitlement.

For contrast, Zipgeist **does** hold it — that is verified from its shipped
entitlements and provisioning profile, recorded in
[research/zipgeist-findings.md](research/zipgeist-findings.md). That is evidence
that the grant is obtainable, not evidence that it is granted to anyone else.

**What an FSKit implementation would additionally require**, none of which is
written yet:

- An `appex` in `Contents/Extensions` conforming to `UnaryFileSystemExtension`.
- `EXExtensionPointIdentifier` = `com.apple.fskit.fsmodule` in its `Info.plist`.
- Security-scoped access to the archive, and the corresponding entitlement.
- macOS 15.4+ deployment target. **Zipee currently targets 13.0**, so an FSKit
  mount would mean raising the floor for the mount feature or shipping two
  targets.

---

## 4. Signing, notarisation and installation UX

### macFUSE

- Official releases are signed and **notarized by Apple** (per the wiki).
- The legacy kext backend additionally requires the user to approve a system
  extension in System Settings, and historically required enabling third-party
  kexts in Recovery Mode. The wiki's Getting Started page says the FSKit
  backend *"does not require a kernel extension or any security configuration
  changes in Recovery Mode"*.
- The wiki lists macOS-level constraints that also affect kext users:
  third-party kexts do not load when booting from external volumes, or inside
  a VM.

### Zipee

- Shipped entitlements are deliberately minimal and sandboxed. See
  [`Zipee.entitlements`](../macos/Zipee/Resources/Zipee.entitlements).
- **No Developer ID certificate or notarisation credentials exist in this
  environment**, so nothing signed can be produced here.
- Zipee's own signing path is implemented but unexercised; see
  [platform-limitations.md](platform-limitations.md) §9.

### UX, stated plainly

| Approach | What the user experiences |
|---|---|
| FSKit mount (with the grant) | Install Zipee, enable the file-system extension in System Settings. Comparable to what Zipgeist does — and its installer script shows how fiddly that is: a 30-second polling loop plus a `lsregister -trusted` re-registration. |
| macFUSE FSKit backend | Install Zipee, **and** install macFUSE separately. Two installers, two approval surfaces. Zipee must detect macFUSE's absence and degrade gracefully. |
| In-app browsing (today) | One installer, no extensions to approve, nothing in System Settings. |

---

## 5. Toolchain availability — verified

From macOS CI runs on this repository:

| Run | Image | OS | Xcode | SDK |
|---|---|---|---|---|
| 38710196592 | `macos-14` | macOS 14.8.9 (23J631) | 15.4 (15F31d) | macOS 15.4 |

Two consequences:

1. **The macOS 15.4 SDK is present on the runner**, so FSKit is compilable in
   CI. That is enough to *type-check* an FSKit extension, though not to
   exercise mounting, which needs a real volume and user approval.
2. The older image is not ideal. The workflow now also runs `macos-15`, which
   carries a newer SDK.

**Not verified:** whether any available runner image can mount and exercise an
FSKit volume in an automated, headless way. That is the open question below.

---

## 6. Recommendation

1. **Ship in-app browsing now.** It is tested, it needs no entitlement, and it
   has no installation burden. This is the product boundary this repository
   maintains.
2. **Apply for `com.apple.developer.fskit.fsmodule` in parallel.** It is free,
   it is the technically correct route, and it can be granted while other work
   proceeds. Approval time is unknown.
3. **Do not build against macFUSE until the commercial licence question is
   answered in writing.** The licence explicitly forbids the automated install
   that would make it seamless, and bundling requires payment.
4. **Keep the filesystem adapter platform-agnostic.** It now exists, it is
   tested on Linux, and either backend can implement it without touching the
   engine's safety rules.

---

## 7. Open questions

Unresolved, and not guessed at anywhere in this repository:

1. Can a third party link against a user-installed macFUSE in a commercial
   app, and at what cost? *(licensing; only the author can answer)*
2. How long does an FSKit managed-capability request take, and what are the
   stated criteria? *(Apple)*
3. Does the macFUSE FSKit backend implement the complete read-only operation
   set, with correct semantics, for a non-POSIX payload? *(needs a Mac)*
4. Can a GitHub-hosted macOS runner mount an FSKit volume headlessly, or does
   mounting require interactive approval? *(needs an experiment)*
5. What are the real I/O characteristics of reading archive members through
   per-operation FSKit callbacks? *(needs a Mac)*
6. Does `FSRequiresSecurityScopedPathURLResources` (which Zipgeist declares)
   impose constraints a non-App-Store app would need to work around?

**The next concrete blocker is item 1 or 2**, because both gate any mount work
and both are answerable this week by sending an email or a form — unlike
everything else here, which needs hardware.