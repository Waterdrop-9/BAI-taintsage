package com.bai.env.funcs;

import com.bai.checkers.MemoryCorruption;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.MemoryEvent;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.util.GlobalState;
import com.bai.util.NativePrimitiveCatalog;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.ConsoleTaskMonitor;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class NativeReleaseSummary {
    private final Function function;
    private final Function primitive;
    private final PcodeOp effect;
    private final ALoc parameter;
    private final List<ALoc> preserved;
    private final List<ALoc> clobbered;
    private final int stackPop;
    private final SummaryCondition condition;

    private NativeReleaseSummary(Function function, Function primitive, PcodeOp effect, ALoc parameter,
            List<ALoc> preserved, List<ALoc> clobbered, int stackPop, SummaryCondition condition) {
        this.function = function;
        this.primitive = primitive;
        this.effect = effect;
        this.parameter = parameter;
        this.preserved = List.copyOf(preserved);
        this.clobbered = List.copyOf(clobbered);
        this.stackPop = stackPop;
        this.condition = condition;
    }

    public Function function() { return function; }

    public static NativeReleaseSummary bind(JsonNode model, String binarySha256,
            DecompInterface decompiler) throws Exception {
        require(binarySha256.equals(model.path("binary_sha256").asText()), "Summary binary identity mismatch");
        Set<String> fields = new HashSet<>();
        model.fieldNames().forEachRemaining(fields::add);
        require(fields.equals(Set.of("binary_sha256", "facts_digest", "primitive_catalog_digest", "function_entry",
                "effect_instruction_address", "argument_index", "parameter_storage", "evidence_operation_ids",
                "clobber_return_and_volatile_state", "native_validation_required", "condition")), "Invalid summary fields");
        require(model.path("facts_digest").asText().matches("[0-9a-f]{64}"), "Missing facts identity");
        byte[] catalog = new ObjectMapper().enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .writeValueAsBytes(NativePrimitiveCatalog.document(binarySha256));
        String catalogDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(catalog));
        require(catalogDigest.equals(model.path("primitive_catalog_digest").asText()), "Primitive catalog identity mismatch");
        require(model.path("native_validation_required").isBoolean() && model.get("native_validation_required").booleanValue()
                && model.path("clobber_return_and_volatile_state").isBoolean()
                && model.get("clobber_return_and_volatile_state").booleanValue(), "Unsafe summary execution contract");
        JsonNode evidence = model.path("evidence_operation_ids");
        require(evidence.isArray() && !evidence.isEmpty(), "Missing effect evidence");
        Set<String> evidenceIds = new HashSet<>();
        for (JsonNode identity : evidence) {
            require(identity.isTextual() && !identity.textValue().isBlank() && evidenceIds.add(identity.textValue()),
                    "Invalid effect evidence identities");
        }
        var program = GlobalState.currentProgram;
        Address entry = program.getAddressFactory().getAddress(model.path("function_entry").asText());
        Function function = entry == null ? null : program.getFunctionManager().getFunctionAt(entry);
        require(function != null && !function.isExternal() && !function.isThunk() && !function.hasNoReturn()
                && !function.hasCustomVariableStorage() && function.getCallFixup() == null, "Unsupported summary function");
        Address site = program.getAddressFactory().getAddress(model.path("effect_instruction_address").asText());
        require(site != null && function.getBody().contains(site), "Effect anchor is outside the function");
        var instruction = program.getListing().getInstructionAt(site);
        require(instruction != null, "Effect anchor is not an instruction");
        PcodeOp effect = null;
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALL) {
                require(effect == null, "Effect anchor is ambiguous");
                effect = operation;
            }
        }
        require(effect != null && effect.getNumInputs() == 1 && effect.getInput(0).isAddress(), "Effect anchor is not a direct call");
        Function primitive = program.getFunctionManager().getFunctionAt(effect.getInput(0).getAddress());
        if (primitive != null && primitive.isThunk()) { primitive = primitive.getThunkedFunction(true); }
        require(primitive != null && primitive.isExternal()
                && FunctionModelManager.getExternalFunction(primitive.getName()) instanceof FreeFunction,
                "Effect anchor is not a native release primitive");
        JsonNode storage = model.path("parameter_storage");
        require(storage.isObject() && storage.size() == 3 && storage.path("byte_length").isIntegralNumber() && storage.path("byte_length").canConvertToInt()
                && model.path("argument_index").isIntegralNumber() && model.get("argument_index").canConvertToInt(),
                "Invalid parameter storage");
        int width = storage.get("byte_length").intValue();
        int index = model.get("argument_index").intValue();
        require(width == program.getDefaultPointerSize() && index >= 0, "Unsupported pointer parameter width");
        var register = program.getRegister(storage.path("register_name").asText());
        Address storageAddress = program.getAddressFactory().getAddress(storage.path("address").asText());
        require(register != null && register.getMinimumByteSize() == width && register.getAddress().equals(storageAddress),
                "Parameter register does not match native storage");
        var result = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
        require(result.decompileCompleted() && result.getHighFunction() != null, "Native parameter recovery is incomplete");
        var prototype = result.getHighFunction().getFunctionPrototype();
        require(index < prototype.getNumParams() && !prototype.isVarArg(), "Native parameter is unavailable");
        var symbol = prototype.getParam(index);
        var recovered = symbol.getStorage();
        require(symbol.getCategoryIndex() == index && recovered != null && !recovered.isForcedIndirect()
                && !recovered.isAutoStorage() && recovered.getVarnodeCount() == 1
                && recovered.getFirstVarnode().getAddress().equals(storageAddress)
                && recovered.getFirstVarnode().getSize() == width, "Native parameter recovery disagrees with summary");
        NativeReleaseBody body = NativeReleaseBody.validate(result.getHighFunction(), model.get("condition"),
                index, new Varnode(storageAddress, width), effect);
        PrototypeModel convention = function.getCallingConvention();
        if (convention == null) { convention = program.getCompilerSpec().getDefaultCallingConvention(); }
        require(convention != null && !convention.hasInjection(), "Unsupported calling convention");
        int pop = GlobalState.arch.isX86() ? width : 0;
        require(convention.getExtrapop() == pop && convention.getStackshift() == pop, "Unsupported summary stack convention");
        PrototypeModel releaseConvention = primitive.getCallingConvention();
        if (releaseConvention == null) { releaseConvention = program.getCompilerSpec().getDefaultCallingConvention(); }
        require(releaseConvention != null && !releaseConvention.hasInjection()
                && releaseConvention.getExtrapop() == pop && releaseConvention.getStackshift() == pop,
                "Unsupported native release calling convention");
        SummaryMachineEffects.validate(function, site, releaseConvention, pop, body);
        List<ALoc> preserved = new ArrayList<>();
        for (Varnode location : convention.getUnaffectedList()) {
            if (location.isRegister()) { preserved.add(ALoc.getALoc(location)); }
        }
        require(!preserved.isEmpty(), "Calling convention lacks preserved registers");
        List<ALoc> clobbered = new ArrayList<>();
        for (var candidate : program.getLanguage().getRegisters()) {
            if (!candidate.equals(candidate.getBaseRegister()) || candidate.getMinimumByteSize() == 0) { continue; }
            ALoc location = ALoc.getALoc(new Varnode(candidate.getAddress(), candidate.getMinimumByteSize()));
            if (!location.isSP() && !location.isPC()) { clobbered.add(location); }
        }
        return new NativeReleaseSummary(function, primitive, effect,
                ALoc.getALoc(new Varnode(storageAddress, width)), preserved, clobbered, pop, body.condition());
    }

    public boolean apply(PcodeOp call, Context caller, AbsEnv environment) {
        SummaryCondition.Decision decision = condition == null ? SummaryCondition.Decision.RELEASE : condition.evaluate(environment);
        if (decision == SummaryCondition.Decision.DEFER) { return false; }
        if (decision == SummaryCondition.Decision.RELEASE) {
            KSet pointers = environment.get(parameter);
            Context context = Context.getContext(caller, call.getSeqnum().getTarget(), function);
            MemoryEvent event = MemoryEvent.at(effect, context, "release");
            if (pointers.isNormal()) {
                for (AbsVal pointer : pointers) {
                    if (pointer.getRegion().isHeap()) {
                        MemoryCorruption.checkDoubleFree(pointer, environment, event, primitive, 0);
                    }
                }
            }
            FreeFunction.releasePointers(pointers, environment, event);
        }
        Map<ALoc, KSet> saved = new LinkedHashMap<>();
        for (ALoc location : preserved) { saved.put(location, environment.get(location)); }
        for (ALoc location : clobbered) { environment.set(location, KSet.getTop(), true); }
        for (var cell : saved.entrySet()) { environment.set(cell.getKey(), cell.getValue(), true); }
        if (stackPop != 0) {
            ALoc stack = ALoc.getSPALoc();
            KSet adjusted = environment.get(stack).add(new KSet(stack.getLen() * 8).insert(new AbsVal(stackPop)));
            environment.set(stack, adjusted, true);
        }
        return true;
    }

    private static void require(boolean valid, String reason) {
        if (!valid) { throw new IllegalArgumentException(reason); }
    }
}
