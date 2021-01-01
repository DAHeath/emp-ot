#include <emp-tool/emp-tool.h>
#include "emp-ot/ferret.h"
#include <iostream>


template <typename T>
double test_rcot(T* ot, NetIO& io, int party, int length) {
  GT::PRG prg;

  auto start = clock_start();

  auto b = ot->extend(io, prg, length);

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

const static int threads = 1;

int main(int argc, char** argv) {
  int length = 1<<24, port, party;
  parse_party_and_port(argv, &party, &port);

  if (party == ALICE) {
    NetIO io { nullptr, port };
    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Semihonest, Role::Sender, threads>::make(io, prg);
      std::cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, io, party, length)*1e6<<" OTps"<<endl;
    }

    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Malicious, Role::Sender, threads>::make(io, prg);
      std::cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, io, party, length)*1e6<<" OTps"<<endl;
    }
  } else {
    NetIO io { "127.0.0.1",port };
    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Semihonest, Role::Receiver, threads>::make(io, prg);
      std::cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, io, party, length)*1e6<<" OTps"<<endl;
    }
    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Malicious, Role::Receiver, threads>::make(io, prg);
      std::cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, io, party, length)*1e6<<" OTps"<<endl;
    }
  }
}

