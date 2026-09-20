package com.bai.env.funcs;

import com.bai.env.funcs.externalfuncs.AtoiFunction;
import com.bai.env.funcs.externalfuncs.CallocFunction;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.funcs.externalfuncs.FgetcFunction;
import com.bai.env.funcs.externalfuncs.FgetsFunction;
import com.bai.env.funcs.externalfuncs.FprintfFunction;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.env.funcs.externalfuncs.FscanfFunction;
import com.bai.env.funcs.externalfuncs.GetcFunction;
import com.bai.env.funcs.externalfuncs.GetenvFunction;
import com.bai.env.funcs.externalfuncs.GetsFunction;
import com.bai.env.funcs.externalfuncs.LibcStartMainFunction;
import com.bai.env.funcs.externalfuncs.MallocFunction;
import com.bai.env.funcs.externalfuncs.MallocUsableSizeFunction;
import com.bai.env.funcs.externalfuncs.MemcpyFunction;
import com.bai.env.funcs.externalfuncs.PrintfFunction;
import com.bai.env.funcs.externalfuncs.PutsFunction;
import com.bai.env.funcs.externalfuncs.RandFunction;
import com.bai.env.funcs.externalfuncs.ReadFunction;
import com.bai.env.funcs.externalfuncs.ReallocFunction;
import com.bai.env.funcs.externalfuncs.RecvFunction;
import com.bai.env.funcs.externalfuncs.ScanfFunction;
import com.bai.env.funcs.externalfuncs.SnprintfFunction;
import com.bai.env.funcs.externalfuncs.SprintfFunction;
import com.bai.env.funcs.externalfuncs.SscanfFunction;
import com.bai.env.funcs.externalfuncs.StrcatFunction;
import com.bai.env.funcs.externalfuncs.StrchrFunction;
import com.bai.env.funcs.externalfuncs.StrcpyFunction;
import com.bai.env.funcs.externalfuncs.StrlenFunction;
import com.bai.env.funcs.externalfuncs.StrncpyFunction;
import com.bai.env.funcs.externalfuncs.TopResultFunction;
import com.bai.env.funcs.stdfuncs.CppStdModelBase;
import com.bai.env.funcs.stdfuncs.ListModel;
import com.bai.env.funcs.stdfuncs.MapModel;
import com.bai.env.funcs.stdfuncs.VectorModel;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FunctionModelManager
 */
public class FunctionModelManager {

    private static final List<ExternalFunctionBase> EXTERNAL_FUNCTION_LIST = List.of(
            new LibcStartMainFunction(),
            new TopResultFunction(),
            // Heap function
            new MallocFunction(),
            new CallocFunction(),
            new ReallocFunction(),
            new FreeFunction(),
            new MallocUsableSizeFunction(),
            // String function
            new StrcatFunction(),
            new StrlenFunction(),
            new StrcpyFunction(),
            new StrncpyFunction(),
            // Taint source functions
            new GetcFunction(),
            new FgetcFunction(),
            new GetsFunction(),
            new FgetsFunction(),
            new ReadFunction(),
            new RecvFunction(),
            new GetenvFunction(),
            new RandFunction(),
            // Taint source functions with varargs
            new ScanfFunction(),
            new SscanfFunction(),
            new FscanfFunction(),
            new StrchrFunction(),
            // varargs functions
            new PrintfFunction(),
            new SnprintfFunction(),
            new FprintfFunction(),
            new SprintfFunction(),
            // stdlib
            new MemcpyFunction(),
            new AtoiFunction(),
            new PutsFunction()
    );

    private static final List<CppStdModelBase> STD_MODEL_LIST = List.of(
            new ListModel(),
            new MapModel(),
            new VectorModel()
    );

    private static final Pattern STL_MODEL_NAME_PATTERN = Pattern.compile("(\\w+)<.*allocator.*>");
    private static final Map<String, ExternalFunctionBase> symbol2ExternalFunctionMap = new HashMap<>();
    private static final Map<Address, String> address2SymbolConfigMap = new HashMap<>();
    private static final Map<String, CppStdModelBase> symbol2StdModelMap = new HashMap<>();


    private static void initSymbol2ExternalFunctionMap() {
        for (ExternalFunctionBase functionModel : EXTERNAL_FUNCTION_LIST) {
            for (String symbol : functionModel.getSymbols()) {
                if (symbol2ExternalFunctionMap.put(symbol, functionModel) != null) {
                    Logging.debug("\"" + symbol + "\"" + " already existed, please check.");
                }
            }
        }
    }

    private static void initSymbol2StdModelMap() {
        for (CppStdModelBase stdModel: STD_MODEL_LIST) {
            for (Object symbol: stdModel.getSymbols()) {
                if (symbol2StdModelMap.put((String) symbol, stdModel) != null) {
                    Logging.debug("C++ std::\"" + symbol + "\"" + " already existed, please check.");
                }
            }
        }
    }

    public record StdCallModel(CppStdModelBase<?> model, CppStdModelBase.Handler handler) { }

    public static StdCallModel resolveStd(Function function) {
        Namespace namespace = function.getParentNamespace();
        boolean standard = false;
        while (namespace != null && !namespace.isGlobal()) {
            if (namespace.getName().equals("std") && namespace.getParentNamespace().isGlobal()) {
                standard = true;
                break;
            }
            namespace = namespace.getParentNamespace();
        }
        if (!standard) { return null; }
        Matcher matcher = STL_MODEL_NAME_PATTERN.matcher(function.getParentNamespace().getName());
        if (!matcher.find()) { return null; }
        CppStdModelBase<?> model = symbol2StdModelMap.get(matcher.group(1));
        if (model == null) { return null; }
        CppStdModelBase.Handler handler = model.resolve(function);
        return handler == null ? null : new StdCallModel(model, handler);
    }

    /** Get registered external function model.
    * @param symbol the symbol string.
    * @return the external function model or null if not registered.
    */
    public static ExternalFunctionBase getExternalFunction(String symbol) {
        return symbol2ExternalFunctionMap.get(symbol);
    }

    public static Map<String, ExternalFunctionBase> getRegisteredExternalFunctions() {
        return Map.copyOf(symbol2ExternalFunctionMap);
    }

    /**
     * Register a mapping from address to symbol.
     * @param address the address.
     * @param symbol the symbol string.
     * @return the old symbol if address already registered, otherwise null.
     */
    public static String mapAddress2Symbol(Address address, String symbol) {
        return address2SymbolConfigMap.put(address, symbol);
    }

    /**
     * Checks if the function entry address is mapped to a symbol.
     * @param entryAddress the function entry address.
     * @return true if the address is mapped, otherwise false.
     */
    public static boolean isFunctionAddressMapped(Address entryAddress) {
        return address2SymbolConfigMap.containsKey(entryAddress);
    }

    /**
     * Reset the address to symbol mapping.
     */
    public static void resetConfig() {
        address2SymbolConfigMap.clear();
    }

    /**
     * Reset all the containers in registered std models.
     */
    public static void resetStdContainers() {
        for (CppStdModelBase stdModel: symbol2StdModelMap.values()) {
            stdModel.resetPool();
        }
    }

    /**
     * Initialize all registered function models.
     */
    public static void initAll() {
        initSymbol2ExternalFunctionMap();
        initSymbol2StdModelMap();
    }
}
