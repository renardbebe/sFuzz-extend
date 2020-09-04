#pragma once
#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

class OracleFactory {
    MultipleFunction functions;
    SingleFunction function;
    vector<int> vulnerabilities;
    vector<vector<OpcodeContext> > vulnerable_funcs;
  public:
    void initialize();
    void finalize();
    void save(OpcodeContext ctx);
    pair<vector<int>, vector<vector<OpcodeContext> > > analyze();
};
