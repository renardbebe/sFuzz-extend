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
  public:
    void initialize();
    void finalize();
    void save(OpcodeContext ctx);
    vector<int> analyze();
};
