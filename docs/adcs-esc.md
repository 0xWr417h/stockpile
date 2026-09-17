# ADCS ESC Adversary Emulation Plugin for Caldera

A Caldera/stockpile plugin that autonomously emulates Active Directory Certificate
Services (AD CS) privilege escalation via ESC1-4. The plugin enumerates vulnerable
certificate templates, branches into the correct exploitation path based on discovered
facts, and recovers the domain administrator NT hash via PKINIT UnPAC-the-Hash. The
recovered hash is emitted as stockpile-native facts (`domain.user.name`,
`domain.user.ntlm`) for chaining into existing lateral-movement abilities.

Both Linux (certipy) and Windows (Certify/Rubeus via Process.Start) executors are included
under the same ability IDs. Caldera selects the appropriate executor per agent OS.
The adversary profiles and fact contract are identical across platforms.

---

## Guardrails

- **Lab use only.** Run exclusively against AD infrastructure, CAs, and templates
  you own and are authorised to test against.
- **ESC4 modifies AD state.** It rewrites a certificate template, then restores it
  during cleanup. Snapshot the DC before running ESC4. Confirm the restore succeeded
  before moving on.

---

## Architecture: fact-driven branching

The enumeration ability runs `certipy find -vulnerable -json` (Linux) or
`Certify.exe find /vulnerable` (Windows) and passes output to `esc_find`, which
emits per-ESC typed facts:

```
esc1.template.name  --issued_by-->  esc1.ca.name
esc2.template.name  --issued_by-->  esc2.ca.name
esc3.template.name  --issued_by-->  esc3.ca.name
esc4.template.name  --issued_by-->  esc4.ca.name
```

Each request ability references only its own ESC facts. An ability whose fact
variables are never filled does not run. The planner fires only the branches for ESC
classes that were actually found - no conditional logic, no value-comparison
requirements.

Successful request abilities echo the written `.pfx` path, captured by `esc_pfx`
into `esc.cert.pfx`. The shared auth ability runs once per `esc.cert.pfx`, so every
branch feeds the same UnPAC-the-Hash step.

### ESC2 / ESC3 dual-flag

certipy flags Any Purpose EKU templates as both ESC2 and ESC3 (an Any Purpose cert
is enrollment-agent capable). This means `esc3.template.name` may hold multiple
values, and the planner fires one ESC3 link per value. This is correct behaviour:
the output filename embeds the template name so links never overwrite each other.

---

## Status

| Ability | Linux | Windows |
|---------|-------|---------|
| Enumerate | certipy find (JSON) | Certify find (text), Process.Start |
| ESC1 | certipy req | Certify + Rubeus, Process.Start |
| ESC2 | certipy req (2-step) | Certify 2-step, Process.Start |
| ESC3 | certipy req (2-step) | Certify 2-step, Process.Start, dual-link |
| ESC4 | certipy template + req | [ADSI] rewrite + Certify, Process.Start + restore |
| Auth / UnPAC | certipy auth | Rubeus asktgt /getcredentials, Process.Start |

All branches validated end-to-end against a live lab (certipy v5.1.0, Certify
v1.1.0, Rubeus v2.2.0, Caldera/stockpile 5.3.0).

### Platform coverage

| Role | Platform | Status |
|------|----------|--------|
| Agent | Ubuntu 24.04 | ✓ all branches |
| Agent | Windows 10 | ✓ all branches |
| Agent | Windows 11 | ✓ all branches |
| Infrastructure (DC) | Windows Server 2022 | ✓ target of all AD/Kerberos operations |
| Infrastructure (CA) | Windows Server 2022 | ✓ issued certificates across all ESC branches |
| Agent | Windows Server (any) | not yet validated |

Windows Server as an agent target has not been explicitly tested. PS5.1 and .NET
Framework 4.8 are present on Server 2019 and 2022, so the executors are expected
to work, but the `-WorkingDirectory` sandcat launch requirement and Defender
exclusion notes apply equally.

---

## File layout

```
caldera/plugins/stockpile/data/abilities/discovery/
  5a78c209-856c-494b-b64f-54974a102307.yml    Enumerate Vulnerable Certificate Templates

caldera/plugins/stockpile/data/abilities/privilege-escalation/
  eabc40cb-d298-4a93-9c1c-d4897721dfd9.yml    ESC1: Request Certificate as Administrator
  a012ff25-3388-4331-8fdb-cda6e81d7931.yml    ESC2: Any-Purpose On-Behalf-Of Administrator
  53f2175d-d16d-41c6-bce3-fb573f83ca79.yml    ESC3: Enrollment Agent On-Behalf-Of Administrator
  f33a18f2-2e34-4431-856f-dafe447bdedc.yml    ESC4: Reconfigure Template then Enroll

caldera/plugins/stockpile/data/abilities/credential-access/
  991863ce-f186-421f-ad22-4980bc3ab243.yml    Authenticate with Certificate (UnPAC-the-Hash)

caldera/plugins/stockpile/data/adversaries/
  855fbd59-26b2-4251-b19d-d65b45210188.yml    ADCS ESC1 to Domain Admin
  bd73c55d-3ac6-47db-8175-16a8bdcda6fa.yml    ADCS ESC2 to Domain Admin
  40bdbc64-5355-465d-9fcb-23706757eeb5.yml    ADCS ESC3 to Domain Admin
  5cafc663-ec7c-46fa-9470-0f580d3564e6.yml    ADCS ESC4 to Domain Admin
  0e985571-e632-4273-a734-081df60cab4f.yml    ADCS Multi-ESC Sweep (ESC1-4)

caldera/plugins/stockpile/data/sources/
  adcs_esc_source.yml                         Fact source (edit with lab values)

caldera/plugins/stockpile/app/parsers/
  esc_find.py    certipy JSON + Certify text -> per-ESC facts (dual-format)
  esc_pfx.py     captures issued .pfx path into esc.cert.pfx
  esc_auth.py    certipy + Rubeus output -> domain.user.ntlm (dual-format)

caldera/plugins/stockpile/data/payloads/
  Certify.exe    GhostPack Certify v1.0.0 (Windows executor payload)
  Rubeus.exe     GhostPack Rubeus v2.2.0+  (Windows executor payload)
```

---

## Install

```bash
# Parsers
cp parsers/esc_find.py parsers/esc_auth.py parsers/esc_pfx.py \
   /path/to/caldera/plugins/stockpile/app/parsers/

# Abilities
cp abilities/discovery/*.yml \
   /path/to/caldera/plugins/stockpile/data/abilities/discovery/
cp abilities/privilege-escalation/*.yml \
   /path/to/caldera/plugins/stockpile/data/abilities/privilege-escalation/
cp abilities/credential-access/*.yml \
   /path/to/caldera/plugins/stockpile/data/abilities/credential-access/

# Adversaries and source
cp adversaries/*.yml  /path/to/caldera/plugins/stockpile/data/adversaries/
cp sources/adcs_esc_source.yml.example \
   /path/to/caldera/plugins/stockpile/data/sources/adcs_esc_source.yml
# Edit adcs_esc_source.yml with your lab values before running

# Windows payloads (compile from GhostPack source)
cp Certify.exe Rubeus.exe \
   /path/to/caldera/plugins/stockpile/data/payloads/
```

Restart the Caldera server after installing.

---

## Linux agent prerequisites

- `certipy-ad` installed on the agent host
- Network reachability to the DC (LDAP) and CA (RPC/445)
- Low-privilege domain credentials seeded in the fact source

The Linux executors run certipy from the operator/agent host, reaching the CA
remotely over the network. No offensive tooling runs on the victim endpoint.

**Key fact:** `-target` must be the CA's DNS or NetBIOS name, never its IP.
certipy uses this as the SMB/NetBIOS remote name; an IP causes a timeout.
Supply `-target-ip` separately to skip DNS resolution. Both are in the fact source
as `esc.ca.host` and `esc.ca.ip`.

---

## Windows agent prerequisites

- Sandcat agent running in the low-privilege domain user's context
- `Certify.exe` and `Rubeus.exe` in `caldera/plugins/stockpile/data/payloads/`
  Compile from source (recommended):
  - Certify: `github.com/GhostPack/Certify` at commit `a0315dfb` (null-ref fix, last v1.x before 2.0 rewrite)
  - Rubeus: `github.com/GhostPack/Rubeus` master, target .NET 4 or 4.5
  Build as Release in Visual Studio. No special build configuration required - the
  executors use `Process.Start` so architecture (x86/AnyCPU) and dependency
  embedding are irrelevant.

  Verified working binaries (tested on Win10 and Win11, x86 precompiled):

  | Binary | SHA256 | Source | Size |
  |--------|--------|--------|------|
  | Certify.exe | `af5c3a5f68323ac68b258dae37c20e48f594118d08479f92a78bd54d26debd9a` | depradip/Ghostpack_CompiledBinaries | 174080 bytes |
  | Rubeus.exe | `1bfbefa4ff4d0df3ee0090b5079cf84ed2e8d5377ba5b7a30afd88367d57b9ff` | depradip/Ghostpack_CompiledBinaries | 446976 bytes |

  These are community-compiled x86 binaries, not official GhostPack releases.
  Verify hashes before use in any environment outside your own lab.
- Network reachability to the DC and CA
- Sandcat **must be launched with `-WorkingDirectory` set to a writable path** where
  payloads will be delivered. The executors use `[IO.Directory]::GetCurrentDirectory()`
  to locate payloads; if sandcat's CWD is `C:\Windows\System32` (the default when
  PowerShell is opened from the Start menu on Windows 11), payload delivery and
  execution will fail. Recommended launch pattern:

  ```powershell
  Start-Process -FilePath C:\Users\Public\sandcat.exe `
    -ArgumentList "-server http://<caldera>:8888 -group red" `
    -WorkingDirectory "C:\Users\Public" `
    -WindowStyle hidden
  ```

- **Windows Defender exclusions required** for the payload delivery path. Defender
  recognises Certify and Rubeus by signature and will quarantine them on delivery
  before the executor can read them. Add exclusions before running any operation:

  ```powershell
  # Run as Administrator on the Windows agent
  Add-MpPreference -ExclusionPath "C:\Users\Public"
  Add-MpPreference -ExclusionProcess "sandcat.exe"   # use your actual sandcat binary name
  ```

  Adjust the path to match your `-WorkingDirectory` if you use a different location.

### Execution model: Process.Start with stdout capture

Caldera delivers each binary as a payload before the link runs. The executor
reads the payload into memory, deletes the Caldera-delivered file immediately, writes
the bytes to a random temp path, then launches it as a child process via
`[Diagnostics.Process]::Start()` with `RedirectStandardOutput` and
`RedirectStandardError` set. After the process exits, the temp binary is deleted and
stdout is written to a second temp file for parsing.

This approach was chosen over `Assembly.Load(byte[])` / `Assembly.LoadFrom()` for
the following reasons, all discovered during validation against Windows 10 and
Windows 11:

- **`Assembly.Load(byte[])` fails on Win11 (64-bit) for x86 assemblies** with
  `BadImageFormatException`. The pre-compiled GhostPack binaries are x86.
  Recompiling as AnyCPU resolves the bitness issue but introduces the next problem.
- **`Assembly.LoadFrom(path)` fails for assemblies with COM interop dependencies**
  when loaded from a temp directory. Certify's `request` command uses
  `Interop.CERTENROLLLib` (Windows Certificate Enrollment COM). When loaded via
  `LoadFrom`, .NET looks for this DLL alongside the temp file - it isn't there.
  Proper embedding via Costura.Fody or ILMerge would resolve this, but requires
  a correctly configured build.
- **`Process.Start` has none of these constraints.** The OS resolves COM interop
  and architecture matching natively, the same way running the binary from a command
  prompt does. Tested on Win10 and Win11, x86 and AnyCPU binaries.

The tradeoff: the binary exists on disk for the duration of the child process
(typically 1-3 seconds for enumeration, slightly longer for certificate requests).
It is deleted immediately after the process exits. The Caldera-delivered copy is
deleted before the child process starts, so the binary exists only at the random
temp path during execution, not at its delivered filename.

The PKCS#1→PFX conversion (Certify emits PEM; Rubeus expects PFX) is done
in-process in the parent via manual DER parsing into `RSAParameters`. `.NET
Framework 4.8` lacks `ImportFromPem` / `ImportRSAPrivateKey` (those are .NET 5+).

### ESC4 Windows: [ADSI] template rewrite

ESC4 Windows uses `[ADSI]` (`System.DirectoryServices.DirectoryEntry`) for the
template rewrite - pure .NET LOTL, no external tools. The four attributes modified
are:

| Attribute | Rewrite value | Restored to |
|-----------|---------------|-------------|
| `msPKI-Certificate-Name-Flag` | 1 (ENROLLEE_SUPPLIES_SUBJECT) | original |
| `pKIExtendedKeyUsage` | Client Auth OID only | original EKU set |
| `msPKI-Certificate-Application-Policy` | Client Auth OID only | original |
| `msPKI-Enrollment-Flag` | 0 | original |

The `nTSecurityDescriptor` (ACL) is intentionally not modified. The assumed-breach
user already holds enrollment rights via the Full Control / All Extended Rights
grants that constitute the ESC4 condition. The backup is written to `$env:TEMP`
before any AD write. Cleanup restores the original values and emits the restored
attribute values to the operation view for confirmation.

### PS5.1 compatibility notes

Windows executors target Windows PowerShell 5.1 (the sandcat runtime). These
constraints and gotchas were discovered during validation:

- **`$pwd.Path` diverges from the process CWD on Win11.** `$pwd` reflects
  PowerShell's FileSystem provider location, which elevated or system-context
  processes on Win11 initialize to `C:\WINDOWS\system32`. Use
  `[IO.Directory]::GetCurrentDirectory()` stored in `$cwd` at the top of the
  command to get the actual .NET process working directory where sandcat delivers
  payloads.
- **Caldera 5.3.0 planner bug: `re_limited = r'#{.*\[*\]}'` with greedy `.*`.**
  The atomic planner scans commands for fact-limit expressions. Its regex matches
  greedily from the first `#{fact}` to the last `]}` in the entire command string.
  If any `#{fact}` variable appears before a `]}` pattern anywhere later in the
  command (including inside scriptblocks), the planner crashes with
  `AttributeError: 'NoneType' object has no attribute 'group'` and fires 0 decisions.
  Fix: avoid `]}` patterns after fact variables. Specifically, use
  `|Select-Object -First 1` instead of `[0]` at the end of scriptblock if-blocks
  (the array indexer creates `]` followed by the if-block closing `}`).
- **`$pwd.Path` diverges from the process CWD on Win11.** `$pwd` reflects
  PowerShell's FileSystem provider location, which elevated or system-context
  processes on Win11 initialize to `C:\WINDOWS\system32`. Use
  `[IO.Directory]::GetCurrentDirectory()` to get the actual .NET process working
  directory, which is where sandcat delivers payloads. Store it in `$cwd` at the
  top of the command rather than calling the method inline (bare method calls as
  cmdlet arguments fail to parse in PS5.1).
- **Multi-valued fact cleanup:** Caldera cleanup commands receive a single fact
  substitution and do not iterate over multi-valued facts. ESC2 and ESC3 Windows
  cleanup uses a wildcard pattern (`adcs_esc*_*_win.pfx`) so both files are removed
  regardless of which template name the planner bound.

---

## ESC4 safety procedure

1. Snapshot the DC before running.
2. Capture a baseline: `certipy template ... -template ESC4 -save-configuration baseline.json`
3. Run the ESC4 adversary with **Auto Close** enabled, and let it finish (do not
   stop manually; cleanup only fires on a clean close).
4. Verify the restore: compare the post-op template state against the baseline.
5. If cleanup does not run (agent death, manual stop), restore by hand from the
   backup retained in `$env:TEMP` (Linux: `/tmp`).

---

## Fact source

Edit `adcs_esc_source.yml` before running:

| Fact | Description |
|------|-------------|
| `esc.domain.fqdn` | Domain FQDN (e.g. `lab.local`) |
| `esc.domain.netbios` | NetBIOS domain name |
| `esc.domain.dc_ip` | Domain controller IP |
| `esc.ca.host` | CA hostname (name, not IP) |
| `esc.ca.ip` | CA IP address |
| `esc.domain.user` | Low-privilege user |
| `esc.domain.password` | Low-privilege password |
| `esc.target.template` | Target template for on-behalf-of requests (ESC2/ESC3 step 2, default: `User`) |

---

## Adversary profiles

| Profile | Branches | Notes |
|---------|----------|-------|
| ADCS ESC1 to Domain Admin | enumerate → ESC1 → auth | |
| ADCS ESC2 to Domain Admin | enumerate → ESC2 → auth | |
| ADCS ESC3 to Domain Admin | enumerate → ESC3 → auth | ESC3 fires twice if an Any Purpose template is present |
| ADCS ESC4 to Domain Admin | enumerate → ESC4 → auth | Modifies AD; requires cleanup |
| ADCS Multi-ESC Sweep (ESC1-4) | enumerate → all branches → auth | All found ESC classes run autonomously |

---

## Detection notes

This plugin is intended to support detection engineering. Key telemetry:

- **CA issuance events (CA: Event ID 4886 / 4887):** Event 4886 records the
  certificate request; 4887 records issuance. Key detection fields:
  - `Requester`: the low-privilege account that submitted the request
    (e.g. `MARVEL\pparker`)
  - `Attributes / ccm`: the machine that submitted the request
    (e.g. `ccm:SPIDERMAN.MARVEL.local`) - useful for correlating the source host
  - `Subject` (4887): the certificate subject as issued. For ESC1/ESC4 abuse this
    is the low-privilege user's distinguished name, while the SAN/UPN names the
    privileged target. The subject/SAN mismatch is the primary detection signal.
  - `RequestId`: correlates the 4886 and 4887 pair and can be matched to the CA
    database entry for full certificate detail including the SAN
  - The absence of a template name in these events is normal; retrieve the template
    from the CA database using the `RequestId` (`certutil -view -restrict
    "RequestID=<id>"`) if needed for triage
- **PKINIT authentication (DC: Event ID 4768):** A Kerberos TGT request using
  certificate pre-authentication (`PreAuthType: 16`) populates the Certificate
  Information fields (`CertIssuerName`, `CertSerialNumber`, `CertThumbprint`),
  which are absent on password-based TGT requests. Key detection fields:
  - `PreAuthType = 16` (PKINIT certificate pre-auth)
  - `CertIssuerName` populated with the internal CA name
  - `TargetUserName` is a privileged account (e.g. Administrator) but the
    `IpAddress` belongs to a low-privilege workstation
  - `TicketEncryptionType = 0x17` (RC4-HMAC) is the default for UnPAC-the-Hash;
    this may differ in hardened environments
- **ESC4 template modification:** Directory service change events on the certificate
  template object, followed by a certificate request and a second modification
  (restore). The rewrite and restore together are a distinct pattern.
- **Enrollment agent requests:** ESC2/ESC3 generate on-behalf-of certificate requests
  (CMC messages with a signer certificate), visible in CA audit logs.

---

## Extending

To add a new ESC class:

1. Add the ESC key to `esc_find.SUPPORTED` and implement detection logic in the
   Certify text branch if the class has a distinct template characteristic.
2. Create a request ability referencing `#{escN.template.name}` / `#{escN.ca.name}`.
3. Add the new ability to the relevant adversary profiles.

The auth ability (`991863ce`) is shared and services any branch that produces
`esc.cert.pfx`. No changes needed there.

---

## Attribution

Techniques: Certified Pre-Owned (Will Schroeder & Lee Christensen, SpecterOps).
certipy by Oliver Lyak (ly4k). Certify and Rubeus by Will Schroeder (GhostPack).
Plugin by Will Swanda (0xWr417h).
