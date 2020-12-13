#include <emp-tool/emp-tool.h>
#include "emp-ot/emp-ot.h"
#include <iostream>
using namespace emp;


template <typename T>
double test_rcot(T* ot, NetIO& io, int party, int length) {
  PRG prg;

  io.sync();
  auto start = clock_start();
  uint64_t mem_size;
  // Call byte_memory_need_inplace() to get the buffer size needed
  mem_size = ot->byte_memory_need_inplace((uint64_t)length);

  std::vector<block> b(mem_size);

  // The RCOTs will be generated directly to this buffer
  ot->extend(io, b);

  long long t = time_from(start);
  io.sync();
  if (party == ALICE) {
    io.send_block(&ot->delta, 1);
    io.send_block(b.data(), mem_size);
  }
  else if (party == BOB) {
    block ch[2];
    ch[0] = zero_block;
    block *b0 = new block[mem_size];
    io.recv_block(ch+1, 1);
    io.recv_block(b0, mem_size);
    for (size_t i = 0; i < mem_size; ++i) {
      b[i] = b[i] ^ ch[getLSB(b[i])];
    }
    if (!cmpBlock(b.data(), b0, mem_size))
      error("RCOT failed");
    delete[] b0;
  }
  std::cout << "Tests passed.\t";
  return t;
}
