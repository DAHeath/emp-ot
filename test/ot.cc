#include <emp-tool/emp-tool.h>
#include "ferret.h"
#include <iostream>


template <typename T>
double test_rcot(T* ot, Link& link, int party, int length) {
  GT::PRG prg;

  auto start = clock_start();
  auto b = ot->extend(link, prg, length);

  long long t = time_from(start);
  if (party == ALICE) {
    link.send((const std::byte*)&ot->delta, 16);
    link.send((const std::byte*)b.data(), 16*b.size());
  }
  else if (party == BOB) {
    std::bitset<128> ch[2];
    ch[0] = 0;
    std::bitset<128>* b0 = new std::bitset<128>[b.size()];
    link.recv((std::byte*)(ch+1), 16);
    link.recv((std::byte*)b0, 16*b.size());
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
    NetLink link { &io };
    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Semihonest, Role::Sender, threads>::make(link, prg);
      std::cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, link, party, length)*1e6<<" OTps"<<endl;
    }

    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Malicious, Role::Sender, threads>::make(link, prg);
      std::cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, link, party, length)*1e6<<" OTps"<<endl;
    }
  } else {
    NetIO io { "127.0.0.1",port };
    NetLink link { &io };
    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Semihonest, Role::Receiver, threads>::make(link, prg);
      std::cout <<"Passive FERRET OT\t"<<double(length)/test_rcot(&ferretcot, link, party, length)*1e6<<" OTps"<<endl;
    }
    {
      GT::PRG prg;
      auto ferretcot = FerretCOT<Model::Malicious, Role::Receiver, threads>::make(link, prg);
      std::cout <<"Active FERRET OT\t"<<double(length)/test_rcot(&ferretcot, link, party, length)*1e6<<" OTps"<<endl;
    }
  }
}

