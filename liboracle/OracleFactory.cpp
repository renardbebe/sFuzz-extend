#include "OracleFactory.h"
#include <string>

using namespace dev;
using namespace eth;
using namespace std;

void OracleFactory::initialize() {
  function.clear();
  uint8_t total = 9;
  while (vulnerable_funcs.size() < total) {
    vector<OpcodeContext> empty_vec;
    vulnerable_funcs.push_back(empty_vec);
  }
}

void OracleFactory::finalize() {
  functions.push_back(function);
  function.clear();
}

void OracleFactory::save(OpcodeContext ctx) {
  function.push_back(ctx);
}

pair<vector<int>, vector<vector<OpcodeContext> > > OracleFactory::analyze() {
  uint8_t total = 9;
  while (vulnerabilities.size() < total) {
    vulnerabilities.push_back(0);
  }
  for (auto function : functions) {
    for (uint8_t i = 0; i < total; i ++) {
      // if (!vulnerabilities[i]) {
        switch (i) {
          case GASLESS_SEND: {
            auto has_gasless_send = false;
            for (auto ctx: function) {
              auto level = ctx.level;
              auto inst = ctx.payload.inst;
              auto gas = ctx.payload.gas;
              auto data = ctx.payload.data;
              
              // vulnerabilities[i] = vulnerabilities[i] || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
              has_gasless_send = has_gasless_send || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
            }
            if (has_gasless_send
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case EXCEPTION_DISORDER: {
            auto rootCallResponse = function[function.size() - 1];
            bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
            bool has_exception_disorder = false;
            for (auto ctx : function) {
              // vulnerabilities[i] = vulnerabilities[i] || (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level);
              has_exception_disorder = has_exception_disorder || (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level);
            }
            if (has_exception_disorder
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case TIME_DEPENDENCY: {
            auto has_transfer = false;
            auto has_timestamp = false;
            for (auto ctx : function) {
              has_transfer = has_transfer || ctx.payload.wei > 0;
              has_timestamp = has_timestamp || ctx.payload.inst == Instruction::TIMESTAMP;
            }
            // vulnerabilities[i] = has_transfer && has_timestamp;
            if (has_transfer && has_timestamp
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case NUMBER_DEPENDENCY: {
            auto has_transfer = false;
            auto has_number = false;
            for (auto ctx : function) {
              has_transfer = has_transfer || ctx.payload.wei > 0;
              has_number = has_number || ctx.payload.inst == Instruction::NUMBER;
            }
            // vulnerabilities[i] = has_transfer && has_number;
            if (has_transfer && has_number
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case DELEGATE_CALL: {
            auto rootCall = function[0];
            auto data = rootCall.payload.data;
            auto caller = rootCall.payload.caller;
            auto has_delegate_call = false;
            for (auto ctx : function) {
              if (ctx.payload.inst == Instruction::DELEGATECALL) {
                // vulnerabilities[i] = vulnerabilities[i]
                //     || data == ctx.payload.data
                //     || caller == ctx.payload.callee
                //     || toHex(data).find(toHex(ctx.payload.callee)) != string::npos;
                has_delegate_call = has_delegate_call
                    || data == ctx.payload.data
                    || caller == ctx.payload.callee
                    || toHex(data).find(toHex(ctx.payload.callee)) != string::npos;
              }
            }
            if (has_delegate_call
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case REENTRANCY: {
            auto has_loop = false;
            auto has_transfer = false;
            for (auto ctx : function) {
              has_loop = has_loop || (ctx.level >= 4 &&  toHex(ctx.payload.data) == "000000ff");
              has_transfer = has_transfer || ctx.payload.wei > 0;
            }
            // vulnerabilities[i] = has_loop && has_transfer;
            if (has_loop && has_transfer
                && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case FREEZING: {
            auto has_delegate = false;
            auto has_transfer = false;
            for (auto ctx: function) {
              has_delegate = has_delegate || ctx.payload.inst == Instruction::DELEGATECALL;
              has_transfer = has_transfer || (ctx.level == 1 && (
                   ctx.payload.inst == Instruction::CALL
                || ctx.payload.inst == Instruction::CALLCODE
                || ctx.payload.inst == Instruction::SUICIDE
              ));
            }
            // vulnerabilities[i] = has_delegate && !has_transfer;
            if (has_delegate && !has_transfer
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case UNDERFLOWING: {
            auto has_underflow = false;
            for (auto ctx: function) {
              // vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isUnderflow;
              has_underflow = has_underflow || ctx.payload.isUnderflow;
            }
            if (has_underflow
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
          case OVERFLOWING: {
            auto has_overflow = false;
            for (auto ctx: function) {
              // vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isOverflow;
              has_overflow = has_overflow || ctx.payload.isOverflow;
            }
            if (has_overflow
              && find(vulnerable_funcs[i].begin(), vulnerable_funcs[i].end(), function[0]) == vulnerable_funcs[i].end()) {
              vulnerabilities[i] += 1;
              vulnerable_funcs[i].push_back(function[0]);
            }
            break;
          }
        }
      // }
    }
  }
  functions.clear();
  return make_pair(vulnerabilities, vulnerable_funcs);
}
