#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
#include <iostream>
using namespace emp;


template <typename T>
double test_rcot(T* ot, NetIO& io, int party, int length) {
  PRG prg;

  auto start = clock_start();

  auto b = ot->extend(io, length);

  long long t = time_from(start);
  io.sync();
  if (party == ALICE) {
    io.send_block((block*)&ot->delta, 1);
    io.send_block((block*)b.data(), b.size());
  }
  else if (party == BOB) {
    std::bitset<128> ch[2];
    ch[0] = 0;
    std::bitset<128>* b0 = new std::bitset<128>[b.size()];
    io.recv_block((block*)ch+1, 1);
    io.recv_block((block*)b0, b.size());
    for (size_t i = 0; i < b.size(); ++i) {
      b[i] ^= ch[b[i][0]];
    }
    for (std::size_t i = 0; i < b.size(); ++i) {
      if (b[i] != b0[i]) {
        error("RCOT failed");
      }
    }
    delete[] b0;
  }
  std::cout << "Tests passed.\t";
  return t;
}
