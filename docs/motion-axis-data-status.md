# Motion axis `<Data Format="Axis">` decode — status and remaining gap

## Summary

| Axis datatype | `<Data>` emitted? | Notes |
| --- | --- | --- |
| `AXIS_VIRTUAL` | **Yes**, all fitting blob lengths | `_render_axis_virtual`; every field read from the blob, nothing hardcoded |
| `AXIS_CIP_DRIVE` | No — documented floor | ~63% of fields decode; blocked by pool-invariant fields (below) |
| `AXIS_SERVO_DRIVE` | No — documented floor | same struct/family as CIP_DRIVE |
| `MOTION_GROUP` | No — documented floor | `MotionGroupParameters`; same class of pool-invariant blocker |

`AXIS_VIRTUAL` is fully handled. The drive axes and the motion group are **held
as a floor**: a present-but-wrong `<Data>` scores worse than the single
`element_missing` it replaces (the comparator counts one diff per missing block
but one diff per *wrong attribute*), so the block must be **100% byte-exact or
not emitted at all**. We can decode most of it but not all of it — see below.

## The config struct (what was reverse-engineered)

The axis configuration is attribute `0x01` (body_mode) of the tag's cip-0x6a
backing record — a **fixed-length little-endian struct, dense and ordered,
keyed by its byte length, and shared across axis types** (a length-5965 blob
carries `AXIS_CIP_DRIVE`, `AXIS_SERVO_DRIVE` and `AXIS_VIRTUAL` at the same
offsets; the axis type only decides which fields the L5X emits). OEM emits the
`<AxisParameters>` attributes in near-struct order and byte offsets increase
monotonically with emit order.

A differential analysis over 849 axis tags from two independent pools
established, for the 5965 layout (366 attributes):

- **231/366 attributes decode byte-exact** — offsets and encodings validated to
  reproduce the OEM string on 100% of instances that emit them. This includes
  151 REALs whose **decorated float text matches OEM exactly** via
  `tag_value._fmt_real_decorated`, plus ints, hex bitfields
  (`tag_value._format_int_radix(..., "Hex")`), 51 enums (byte→string vocabs,
  every offset a collision-free consistent function), two length-prefixed ASCII
  strings, and the four "blocker" fields below.
- **185/186 varying fields** are pinned to a unique real offset.

### The four non-scalar field decoders (validated, reusable)

- `PMMotorFluxSaturation` — `float32` LE array, stride 4, `K=8`.
- `PositionUnits` — inline ASCII string: `u16` LE length prefix, then the chars.
- `CyclicReadUpdateList` — variable-length `u16` code list (count prefix, then
  `count` codes), each code mapped by a fixed vocab to a parameter name.
- `MotorCatalogNumber` — inline ASCII string, same shape as `PositionUnits`.

### Cross-reference fields (resolvable in the converter)

`MotionModule` (module id `u16` LE, plus a channel byte → `:ChN`) and
`MotionGroup` (a group id) decode to *ids* in the blob; their *names* come from
the module/group topology the converter already resolves elsewhere. These are
not a decode defect — they are handled the way `AXIS_VIRTUAL` already resolves
its `MotionGroup`.

## Why it is not landable yet — the hard floor

Roughly **133 attributes per length are pool-invariant**: they hold a single
value across *every* axis tag in both pools (e.g. `ProgrammedStopMode`,
`ServoLoopConfiguration`, `MotorUnit`, the `SafeStoppingAction*` family, the
`*NotchFilter*` gains, the `*DataScaling*` factors, feedback-unit fields). A
field that never varies gives the differential method **no handle to locate its
offset** — any offset holding that constant "matches". Emitting such a field
would mean writing a hardcoded default, which:

1. violates the project's firm no-hardcode rule, and
2. carries **regression risk**: a customer who set a non-default value we have
   only ever seen at default would be rendered wrong, breaking the 0-worse
   guarantee on unseen files.

Because the block is all-or-nothing, these ~133 fields block the entire
`<Data>` even though the other ~231 are solved.

## What would close the gap

Either of:

1. **More-varied ACDs.** The floor is a *data* limit, not a method limit. Adding
   projects that exercise the currently-invariant fields — servo/CIP drives with
   non-default stopping actions, safety stopping configuration, notch filters,
   scaling factors, feedback units, motor-test parameters — makes those fields
   vary, at which point the same differential + struct-order method pins their
   offsets and they become *read* (no hardcode, no regression). Each newly
   varying field is one more removed from the 133.
2. **The CIP Motion axis attribute table** (attribute id + size per firmware).
   That yields every field's offset directly, including the invariant ones, so
   they are read rather than hardcoded.

When the floor lifts, the renderer generalizes `_render_axis_virtual`: a
length-keyed offset/encoding schema plus the four decoders above, gated so a
length emits `<Data>` only when it validates byte-exact across the pool.

## Reproducing / resuming

The method and validated artifacts are preserved in the fidelity workspace under
`motion_recon/`: the extractor (blob ↔ OEM attribute dataset, 849 tags), the
per-length differential solver, the iterative windowed-anchoring reconstructor,
the per-length offset maps, and a string-exact validator that renders every
attribute through the real `tag_value` formatters and compares to OEM. The
string-exact validator is the gate — a length is landable only when it prints
full equality across every instance.
