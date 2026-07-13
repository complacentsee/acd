# V7 correction: convert pre-V10 ACDs that have no QuickInfo.XML

## The defect

V7 (and any pre-V10) ACD projects aborted the entire export with a bare
`FileNotFoundError: QuickInfo.XML`. The cause is a format difference, not a
corrupt file: **pre-V10 ACDs do not contain the `QuickInfo.XML` stream at
all** (nor `TagInfo.XML`). Those XML sidecars were introduced in a later ACD
generation. `ProjectBuilder.build()` read `QuickInfo.XML` unconditionally, so
every project without it crashed before producing any output.

## Why the data is still recoverable

The project graph — controller, tags, datatypes, modules, programs, routines,
and rungs — lives in `Comps.Dat` / `SbRegion.Dat` / `Nameless.Dat`, which
pre-V10 projects carry normally. `QuickInfo.XML` only supplies top-level
metadata (project name, schema version, Studio/firmware revision), all of
which is also available from the controller record. So a missing
`QuickInfo.XML` should degrade, not abort.

## The correction

`ExportL5x.controller()` already guarded its `QuickInfo.XML` read with
`os.path.exists(...)`. `ProjectBuilder` was the one consumer that did not. The
correction makes it consistent:

- `ProjectBuilder.build()` parses `QuickInfo.XML` only when it exists. When it
  is absent, `TargetName` and `SoftwareRevision` come from the controller
  record (`Controller.name`, `major_rev`.`minor_rev`) and the schema revision
  falls back to `1.0`.
- `ExportL5x.project` builds the controller first (cached — no double build)
  and passes it in via `ProjectBuilder(fallback_controller=...)`.

Also fixed: a latent unbound-variable bug where a `QuickInfo.XML` present but
missing a root `Name` attribute left `target_name` undefined and raised
`NameError`. It now falls back to the controller name too.

`TagInfo.XML` absence needed no new handling — `_load_taginfo` was already
best-effort and leaves the layout map empty, at which point the existing
zero-generator fallback in `Tag.to_xml` takes over.

## Result

On the two V7 test projects the recovered **structure matches the reference
converter exactly**: identical Tag, Module, Program, and Rung counts, with the
correct project name, controller name, and firmware major revision (sourced
from the controller record, not a placeholder). They convert to well-formed
L5X instead of aborting.

The residual per-file difference is concentrated in the **value layer**
(`<Data>` / `DataValueMember` bodies and member radix/value attributes). This
is the direct consequence of the missing `TagInfo.XML`: without the datatype
member byte-layouts, packed value images cannot be decoded, so the converter
emits its zero-generator fallback rather than fabricating values. That is a
version-floor limitation of pre-V10 projects, not a decode error — the
structure it emits is faithful. (DataType counts also differ because some
predefined datatype-library entries the reference materializes are
version-dependent, the same class as the existing firmware-skew handling.)

## Verification

- Full-pool gauntlet on the primary QuickInfo-present pool: **0 files worse** —
  the guarded path is byte-identical to the prior unconditional parse whenever
  `QuickInfo.XML` is present.
- Unit suite: green (239 passed).
- flake8 CI selectors (`E9,F63,F7,F82`): clean.
