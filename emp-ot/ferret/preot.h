#ifndef _PRE_OT__
#define  _PRE_OT__
#include "emp-tool/emp-tool.h"
#include "emp-ot/emp-ot.h"
#include "emp-ot/ferret/role.h"
#include <span>

namespace emp {

template <Role role>
class OTPre {
public:
  NetIO* io;
  int length;
  int count;
  int n;
  std::vector<block> pre_data;
  std::unique_ptr<bool[]> bits;

  CCRH ccrh;

  OTPre() { }

  OTPre(NetIO* io, int n)
    : io(io),
      count(0),
      n(n),
      pre_data(2*n),
      bits(new bool[n]) { }

  void pre(std::span<block> data, block delta) {
    if constexpr (role == Role::Sender) {
      ccrh.Hn(pre_data.data(), data.data(), 0, n, pre_data.data()+n);
      xorBlocks_arr(pre_data.data()+n, data.data(), delta, n);
      ccrh.Hn(pre_data.data()+n, pre_data.data()+n, 0, n);
    } else {
      for(int i = 0; i < n; ++i) {
        bits[i] = getLSB(data[i]);
      }
      ccrh.Hn(pre_data.data(), data.data(), 0, n);
    }
  }

  void choose(NetIO* io, const bool* b, std::size_t n) {
    if constexpr (role == Role::Sender) {
      io->recv_data(bits.get()+count, n);
      count += n;
    } else {
      for (int i = 0; i < n; ++i) {
        bits[count + i] = (b[i] != bits[count + i]);
      }
      io->send_data(bits.get()+count, n);
      count +=n;
    }
  }

  void reset() {
    count = 0;
  }

  void send(const block * m0, const  block * m1, int length, NetIO * io2, int s) {
    block pad[2];
    int k = s*length;
    for (int i = 0; i < length; ++i) {
      if (!bits[k]) {
        pad[0] = m0[i] ^ pre_data[k];
        pad[1] = m1[i] ^ pre_data[k+n];
      } else {
        pad[0] = m0[i] ^ pre_data[k+n];
        pad[1] = m1[i] ^ pre_data[k];
      }
      ++k;
      io2->send_block(pad, 2);
    }
  }

  void recv(block* data, const bool* b, int length, NetIO* io2, int s) {
    int k = s*length;
    block pad[2];
    for (int i = 0; i < length; ++i) {
      io2->recv_block(pad, 2);
      int ind = b[i] ? 1 : 0;
      data[i] = pre_data[k] ^ pad[ind];
      ++k;
    }
  }
};

}
#endif// _PRE_OT__
