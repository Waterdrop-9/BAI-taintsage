package com.bai.env.funcs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.KSet;

record SummaryCondition(ALoc parameter, boolean releaseOnZero) {
    enum Decision { RELEASE, SKIP, DEFER }

    Decision evaluate(AbsEnv environment) {
        KSet values = environment.get(parameter);
        if (!values.isNormal() || values.getBits() != parameter.getLen() * 8) { return Decision.DEFER; }
        Boolean zero = null;
        long mask = parameter.getLen() == 8 ? -1L : (1L << parameter.getLen() * 8) - 1;
        for (AbsVal value : values) {
            if (!value.getRegion().isGlobal() || value.isBigVal()) { return Decision.DEFER; }
            boolean current = (value.getOffset() & mask) == 0;
            if (zero != null && zero != current) { return Decision.DEFER; }
            zero = current;
        }
        return zero == null ? Decision.DEFER : zero == releaseOnZero ? Decision.RELEASE : Decision.SKIP;
    }
}
