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
    io.send_block(&ot->delta, 1);
    io.send_block(b.data(), b.size());
  }
  else if (party == BOB) {
    block ch[2];
    ch[0] = zero_block;
    block *b0 = new block[b.size()];
    io.recv_block(ch+1, 1);
    io.recv_block(b0, b.size());
    for (size_t i = 0; i < b.size(); ++i) {
      b[i] = b[i] ^ ch[getLSB(b[i])];
    }
    if (!cmpBlock(b.data(), b0, b.size()))
      error("RCOT failed");
    delete[] b0;
  }
  std::cout << "Tests passed.\t";
  return t;
}
