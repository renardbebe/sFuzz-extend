#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

void OracleFactory::initialize() {
  function.clear();
}

void OracleFactory::finalize() {
  functions.push_back(function);
  function.clear();
}

void OracleFactory::save(OpcodeContext ctx) {
  function.push_back(ctx);
}

vector<int> OracleFactory::analyze() {
  uint8_t total = 9;
  while (vulnerabilities.size() < total) {
    vulnerabilities.push_back(0);
  }
  for (auto function : functions) {
    for (uint8_t i = 0; i < total; i ++) {
      if (!vulnerabilities[i]) {
        switch (i) {
          case GASLESS_SEND: {
            for (auto ctx: function) {
              auto level = ctx.level;
              auto inst = ctx.payload.inst;
              auto gas = ctx.payload.gas;
              auto data = ctx.payload.data;
              // vulnerabilities[i] = vulnerabilities[i] || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
              if (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0)) {
                vulnerabilities[i] += 1;
              }
            }
            break;
          }
          case EXCEPTION_DISORDER: {
            auto rootCallResponse = function[function.size() - 1];
            bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
            for (auto ctx : function) {
              // vulnerabilities[i] = vulnerabilities[i] || (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level);
              if (!rootException && ctx.payload.inst == Instruction::INVALID && ctx.level) {
                vulnerabilities[i] += 1;
              }
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
            if (has_transfer && has_timestamp) {
              vulnerabilities[i] += 1;
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
            if (has_transfer && has_number) {
              vulnerabilities[i] += 1;
            }
            break;
          }
          case DELEGATE_CALL: {
            auto rootCall = function[0];
            auto data = rootCall.payload.data;
            auto caller = rootCall.payload.caller;
            for (auto ctx : function) {
              if (ctx.payload.inst == Instruction::DELEGATECALL) {
                // vulnerabilities[i] = vulnerabilities[i]
                //     || data == ctx.payload.data
                //     || caller == ctx.payload.callee
                //     || toHex(data).find(toHex(ctx.payload.callee)) != string::npos;
                if (data == ctx.payload.data || caller == ctx.payload.callee || toHex(data).find(toHex(ctx.payload.callee)) != string::npos) {
                  vulnerabilities[i] += 1;
                }
              }
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
            if (has_loop && has_transfer) {
              vulnerabilities[i] += 1;
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
            if (has_delegate && !has_transfer) {
              vulnerabilities[i] += 1;
            }
            break;
          }
          case UNDERFLOWING: {
            for (auto ctx: function) {
              // vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isUnderflow;
              if (ctx.payload.isUnderflow) {
                vulnerabilities[i] += 1;
              }
            }
            break;
          }
          case OVERFLOWING: {
            for (auto ctx: function) {
              // vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isOverflow;
              if (ctx.payload.isOverflow) {
                vulnerabilities[i] += 1;
              }
            }
            break;
          }
        }
      }
    }
  }
  functions.clear();
  return vulnerabilities;
}
