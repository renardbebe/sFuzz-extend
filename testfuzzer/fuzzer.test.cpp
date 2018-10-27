#include <iostream>

#include "gtest/gtest.h"
#include <libfuzzer/Fuzzer.h>

using namespace fuzzer;
using namespace std;

TEST(Fuzzer, f) {
  bytes code = fromHex("6080604052600a6000806101000a81548163ffffffff021916908360030b63ffffffff16021790555034801561003457600080fd5b5060405160208061016d83398101806040528101908080519060200190929190505050806000806101000a81548163ffffffff021916908360030b63ffffffff1602179055505060e4806100896000396000f300608060405260043610603f576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063e42a722b146044575b600080fd5b348015604f57600080fd5b50607c600480360381019080803560030b9060200190929190803560030b90602001909291905050506098565b604051808260030b60030b815260200191505060405180910390f35b6000600f82846000809054906101000a900460030b0101019050929150505600a165627a7a72305820fd4319c5003c8193db7c8c0b89e7e5adf51233bac6b4af240edbf3030bea51a60029");
  map<string, vector<string>> abi;
  abi[""] = vector<string>{"int32"};
  abi["add"] = vector<string>{"int32", "int32"};
  Fuzzer fuzzer(code, abi);
  fuzzer.start();
}
