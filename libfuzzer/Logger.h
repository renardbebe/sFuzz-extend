#pragma once
#include <iostream>
#include <thread>
#include <vector>

using namespace std;

namespace fuzzer {
  struct LogStage {
    /* Name of stage */
    string name;
    /* Number of fuzzed test cases */
    int fuzzed;
    /* Number of skip test cases */
    int skip;
    /* Max number of fuzzed test cases */
    int maxFuzzed;
    /* Length of Test case */
    int testLen;
    /* Constructer */
    double duration;
    /* number of new test case */
    int numTest;
    /* current item */
    int errorCount;
    /* Effector map count*/
    int effCount;
    LogStage() {
      name = "";
      fuzzed = 0;
      skip = 0;
      maxFuzzed = 0;
      duration = 0;
      numTest = 0;
      errorCount = 0;
      effCount = 0;
    }
  };
  class Logger {
    thread th;
    public:
      vector<LogStage*> stages;
      int idx;
      void startTimer();
      void endTimer();
  };
}

