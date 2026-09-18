package com.bai.env.funcs;

import com.bai.env.AbsEnv;
import com.bai.env.ALoc;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.env.funcs.externalfuncs.MallocFunction;
import com.bai.env.funcs.externalfuncs.CallocFunction;
import com.bai.env.funcs.externalfuncs.VarArgsFunctionBase;
import com.bai.util.Utils;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class MemoryAccessEffects {
    private static final Set<String> ALLOCATORS = new MallocFunction().getSymbols();
    private static final Set<String> ZERO_ALLOCATORS = new CallocFunction().getSymbols();
    private static final Pattern OUTPUT_CONVERSION = Pattern.compile(
            "%[-+ #0']*[0-9]*(?:\\.([0-9]*))?(?:hh|ll|[hljztL])?([diouxXfFeEgGaAcspn%])");
    public enum Kind { READ, WRITE }

    public static final class Access {
        private final int argumentIndex;
        private final Kind kind;
        private final boolean conditional;

        private Access(int argumentIndex, Kind kind, boolean conditional) {
            this.argumentIndex = argumentIndex;
            this.kind = kind;
            this.conditional = conditional;
        }

        public int getArgumentIndex() { return argumentIndex; }
        public Kind getKind() { return kind; }
        public boolean isConditional() { return conditional; }
    }

    public static final class Result {
        private final List<Access> accesses;
        private final List<String> gaps;

        private Result(List<Access> accesses, List<String> gaps) {
            this.accesses = List.copyOf(accesses);
            this.gaps = List.copyOf(gaps);
        }

        public List<Access> getAccesses() { return accesses; }
        public List<String> getGaps() { return gaps; }
        public boolean isComplete() { return gaps.isEmpty(); }
    }

    private static final class Builder {
        private final List<Access> accesses = new ArrayList<>();
        private final List<String> gaps = new ArrayList<>();

        private void access(int index, Kind kind, boolean conditional) {
            accesses.add(new Access(index, kind, conditional));
        }
    }

    private MemoryAccessEffects() { }

    public static Result resolve(PcodeOp call, AbsEnv env, Function function) {
        Builder result = new Builder();
        String name = function.getName();
        if (FreeFunction.getStaticSymbols().contains(name)
                || ALLOCATORS.contains(name)
                || ZERO_ALLOCATORS.contains(name)
                || name.equals("rand") || name.equals("realloc")) {
            return new Result(result.accesses, result.gaps);
        }
        switch (name) {
            case "strlen": case "wcslen": case "strchr": case "puts":
            case "atoi": case "atol": case "atoll": case "atoq": case "getenv":
                result.access(0, Kind.READ, false);
                break;
            case "strcpy":
                result.access(0, Kind.WRITE, false);
                result.access(1, Kind.READ, false);
                break;
            case "memcpy": case "memmove": case "strncpy":
                int length = positiveLength(function, env, 2, result);
                if (length != 0) {
                    result.access(0, Kind.WRITE, length < 0);
                    result.access(1, Kind.READ, length < 0);
                }
                break;
            case "memset":
                int extent = positiveLength(function, env, 2, result);
                if (extent != 0) { result.access(0, Kind.WRITE, extent < 0); }
                break;
            case "strcmp": case "strcasecmp":
                result.access(0, Kind.READ, false);
                result.access(1, Kind.READ, false);
                break;
            case "strncmp":
                int count = positiveLength(function, env, 2, result);
                if (count != 0) {
                    result.access(0, Kind.READ, count < 0);
                    result.access(1, Kind.READ, count < 0);
                }
                break;
            case "strcat": case "strncat":
                result.access(0, Kind.READ, false);
                result.access(0, Kind.WRITE, false);
                int append = name.equals("strcat") ? 1 : positiveLength(function, env, 2, result);
                if (append != 0) { result.access(1, Kind.READ, append < 0); }
                break;
            case "read": case "recv":
                if (positiveLength(function, env, 2, result) != 0) { result.access(1, Kind.WRITE, true); }
                break;
            case "gets":
                result.access(0, Kind.WRITE, true);
                break;
            case "fgets":
                if (positiveLength(function, env, 1, result) != 0) { result.access(0, Kind.WRITE, true); }
                result.access(2, Kind.READ, true);
                result.access(2, Kind.WRITE, true);
                break;
            case "fgetc": case "getc":
                result.access(0, Kind.READ, false);
                result.access(0, Kind.WRITE, true);
                break;
            case "printf": case "fprintf": case "sprintf": case "snprintf":
                int formatIndex = name.equals("printf") ? 0 : name.equals("snprintf") ? 2 : 1;
                result.access(formatIndex, Kind.READ, false);
                if (name.equals("fprintf")) {
                    result.access(0, Kind.READ, true);
                    result.access(0, Kind.WRITE, true);
                } else if (name.equals("sprintf") || name.equals("snprintf")) {
                    if (!name.equals("snprintf") || positiveLength(function, env, 1, result) != 0) {
                        result.access(0, Kind.WRITE, true);
                    }
                }
                KSet formats = ExternalFunctionBase.getParamKSet(function, formatIndex, env);
                String format = null;
                if (formats.isNormal() && formats.isSingleton()) {
                    AbsVal pointer = formats.iterator().next();
                    StringBuilder text = new StringBuilder();
                    if (!pointer.isBigVal()) {
                        for (int offset = 0; offset < 4096; offset++) {
                            KSet bytes = env.get(ALoc.getALoc(pointer.getRegion(), pointer.getValue() + offset, 1));
                            if (!bytes.isNormal() || !bytes.isSingleton()) { break; }
                            AbsVal value = bytes.iterator().next();
                            if (!value.getRegion().isGlobal() || value.isBigVal()) { break; }
                            if (value.getValue() == 0) {
                                format = text.toString();
                                break;
                            }
                            text.append((char) (value.getValue() & 0xff));
                        }
                    }
                }
                if (format == null) {
                    result.gaps.add("unresolved_format");
                    break;
                }
                int argumentIndex = formatIndex + 1;
                for (int offset = 0; offset < format.length(); offset++) {
                    if (format.charAt(offset) != '%') { continue; }
                    Matcher conversion = OUTPUT_CONVERSION.matcher(format);
                    conversion.region(offset, format.length());
                    if (!conversion.lookingAt()) {
                        result.gaps.add("unsupported_format_conversion:" + offset);
                        break;
                    }
                    offset = conversion.end() - 1;
                    char specifier = conversion.group(2).charAt(0);
                    if (specifier == '%') { continue; }
                    String precision = conversion.group(1);
                    boolean zeroPrecision = precision != null
                            && (precision.isEmpty() || precision.chars().allMatch(c -> c == '0'));
                    if (specifier == 's' && !zeroPrecision) {
                        result.access(argumentIndex, Kind.READ, true);
                    } else if (specifier == 'n') {
                        result.access(argumentIndex, Kind.WRITE, true);
                    }
                    argumentIndex++;
                }
                break;
            case "scanf": case "__isoc99_scanf": case "sscanf": case "fscanf":
                int inputFormat = name.equals("scanf") || name.equals("__isoc99_scanf") ? 0 : 1;
                result.access(inputFormat, Kind.READ, false);
                if (name.equals("sscanf")) { result.access(0, Kind.READ, true); }
                if (name.equals("fscanf")) {
                    result.access(0, Kind.READ, true);
                    result.access(0, Kind.WRITE, true);
                }
                result.gaps.add("unmodeled_input_conversion_effects");
                break;
            default:
                result.gaps.add("unmodeled_memory_effect:" + name);
        }
        FunctionDefinition signature = VarArgsFunctionBase.getVarArgsSignature(Utils.getAddress(call));
        for (Access access : result.accesses) {
            if (function.getParameter(access.argumentIndex) == null
                    && (signature == null || access.argumentIndex >= signature.getArguments().length)) {
                result.gaps.add("missing_argument:" + access.argumentIndex);
            }
        }
        return new Result(result.accesses, result.gaps);
    }

    private static int positiveLength(Function function, AbsEnv env, int index, Builder result) {
        if (function.getParameter(index) == null) {
            result.gaps.add("missing_argument:" + index);
            return -1;
        }
        KSet values = ExternalFunctionBase.getParamKSet(function, index, env);
        if (!values.isNormal()) { return -1; }
        boolean zero = false;
        boolean positive = false;
        for (AbsVal value : values) {
            if (!value.getRegion().isGlobal() || value.isBigVal() || value.getValue() < 0) { return -1; }
            zero |= value.getValue() == 0;
            positive |= value.getValue() > 0;
        }
        return positive && !zero ? 1 : zero && !positive ? 0 : -1;
    }
}
