# TaintSage Integration

BinAbsInspector source based on KeenSecurityLab/BinAbsInspector `658b413`, distributed under GNU GPL version 3; see [LICENSE](LICENSE).

## Source and validation entry points

- [Abstract environments](src/main/java/com/bai/env/AbsEnv.java), [bounded state partitions](src/main/java/com/bai/env/AbsEnvPartitions.java), and [context execution](src/main/java/com/bai/env/Context.java).
- [Heap lifecycle](src/main/java/com/bai/env/HeapLifetime.java), [memory operations](src/main/java/com/bai/checkers/MemoryCorruption.java), and [P-code execution](src/main/java/com/bai/solver/PcodeVisitor.java).
- [Evidence schema and publication](src/main/java/com/bai/util/MemoryEvidenceExporter.java), [analysis outcomes](src/main/java/com/bai/util/AnalysisOutcome.java), and [Ghidra entry point](ghidra_scripts/BinAbsInspector.java).
- [Partition tests](src/test/java/com/bai/env/AbsEnvPartitionsTest.java), [context tests](src/test/java/com/bai/env/ContextLifetimeTest.java), [conditional transfer tests](src/test/java/com/bai/solver/PcodeBranchTest.java), and [evidence tests](src/test/java/com/bai/util/MemoryEvidenceExporterTest.java).

## Build

Use JDK 21, Gradle 8.5, and Ghidra 12.0.4:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
bash ./gradlew buildExtension
bash ./gradlew test --tests com.bai.env.AbsEnvPartitionsTest --tests com.bai.env.ContextLifetimeTest --tests com.bai.solver.PcodeBranchTest --tests com.bai.util.MemoryEvidenceExporterTest
```

Gradle resolves Maven dependencies; the libraries in `lib/` are also required. Install the ZIP under `dist/` as a Ghidra extension. The extension package includes the source ZIP and build scripts.

## Run

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
export TAINTSAGE_BINABS_EVIDENCE_PATH=/absolute/path/evidence.json
./binabsinspector /path/to/binary -disableZ3 -timeout 120 -json -all
```

[The launcher](binabsinspector) defines runtime configuration. Z3-enabled runs require matching native Z3 libraries; use `Z3_LIBRARY_DIR` when they are outside the system library path.
