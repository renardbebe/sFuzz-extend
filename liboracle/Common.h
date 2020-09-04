#pragma once
#include <iostream>
#include <libdevcore/CommonIO.h>
#include <libevm/LegacyVM.h>

using namespace dev;
using namespace eth;
using namespace std;

const uint8_t GASLESS_SEND = 0;
const uint8_t EXCEPTION_DISORDER = 1;
const uint8_t TIME_DEPENDENCY = 2;
const uint8_t NUMBER_DEPENDENCY = 3;
const uint8_t DELEGATE_CALL = 4;
const uint8_t REENTRANCY = 5;
const uint8_t FREEZING = 6;
const uint8_t OVERFLOWING = 7;
const uint8_t UNDERFLOWING = 8;

struct OpcodePayload {
  u256 wei = 0;
  u256 gas = 0;
  u256 pc = 0;
  Instruction inst;
  bytes data;
  Address caller;
  Address callee;
  bool isOverflow = false;
  bool isUnderflow = false;
};

struct OpcodeContext {
  u256 level;
  OpcodePayload payload;

  OpcodeContext(u256 _level, OpcodePayload _payload): level(_level), payload(_payload) {}
  bool operator == (const OpcodeContext &x) const {
		return(level == x.level && 
           (payload.data.size() < 4 ||
           (payload.data.size() >= 4 &&
           payload.data[0] == x.payload.data[0] && 
           payload.data[1] == x.payload.data[1] && 
           payload.data[2] == x.payload.data[2] && 
           payload.data[3] == x.payload.data[3]))
          );
	}
};

using SingleFunction = vector<OpcodeContext>;
using MultipleFunction = vector<SingleFunction>;
