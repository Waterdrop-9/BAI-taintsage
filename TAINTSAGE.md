# TaintSage Integration

Modified version of KeenSecurityLab/BinAbsInspector, based on `658b413`.
Integration date: 2026-09-15. This modified BinAbsInspector is distributed
under GNU GPL version 3; see LICENSE. Original attribution is retained.

## Included Changes

- Existing context handling, referenced map-key width fixes, and first-free diagnostics.
- Heap and FreeFunction retain the first deallocation's call context.
- CWEReport carries structured evidence; MemoryEvidenceExporter produces
  `taintsage.memory_evidence.v1` documents, including binary SHA-256.
- The Ghidra entry point exports evidence before resetting analysis state.
- The command-line wrapper uses environment configuration instead of local paths.

The exporter and structured-evidence changes were integrated from TaintSage's
`scripts/binabs/MemoryEvidenceExporter.java` and `scripts/patches/`.
They now compile directly with the rest of this repository. No prebuilt
BinAbsInspector JAR or source ZIP is required to build this extension.
Do not reapply TaintSage's historical overlay patches to this source tree.

## Build

Use JDK 21, Gradle 8.5, and Ghidra 12.0.4. Set the installation directory:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
./gradlew buildExtension
./gradlew test --tests com.bai.env.region.HeapTest --tests com.bai.env.funcs.stdfuncs.MapModelTest --tests com.bai.util.MemoryEvidenceExporterTest
```

The Gradle wrapper downloads Gradle. Maven dependencies are resolved by Gradle;
the upstream-supplied libraries in `lib/` are also required. Install the ZIP
under `dist/` as a Ghidra extension. Keep this source tree and build instructions
available alongside any distributed binaries, together with dependency notices.

## Run

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
export TAINTSAGE_BINABS_EVIDENCE_PATH=/absolute/path/evidence.json
./binabsinspector /path/to/binary -disableZ3 -timeout 120 -json -all
```

`GHIDRA_HEADLESS` can override the launcher. For Z3-enabled runs, install the
matching native Z3 libraries and set `Z3_LIBRARY_DIR` if they are not on the
system library path. Without the evidence environment variable, ordinary
BinAbsInspector analysis remains available.

## Validation

On 2026-09-15, the full Java source compiled with JDK 21 and Ghidra 12.0.4.
All eight targeted Heap, MapModel, and MemoryEvidenceExporter tests passed.
Mockito was updated to 5.11.0 and JaCoCo to 0.8.12 for JDK 21 compatibility.
The extension ZIP includes the exporter and a source ZIP with build scripts.
The installed production extension was not replaced; full firmware/Juliet
end-to-end validation has not yet been rerun with this newly built extension.
