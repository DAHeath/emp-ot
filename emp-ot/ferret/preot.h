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
  int n;
  std::vector<block> pre_data;
  std::unique_ptr<bool[]> bits;

  CCRH ccrh;

  OTPre() { }

  OTPre(int n) { }

  std::pair<std::vector<block>, std::unique_ptr<bool[]>>
  pre(NetIO* io, const bool* b, std::size_t n, std::span<block> data, block delta) {
    std::vector<block> pre_data(2*n);
    std::unique_ptr<bool[]> bits(new bool[n]);
    if constexpr (role == Role::Sender) {
      ccrh.Hn(pre_data.data(), data.data(), 0, n, pre_data.data()+n);
      xorBlocks_arr(pre_data.data()+n, data.data(), delta, n);
      ccrh.Hn(pre_data.data()+n, pre_data.data()+n, 0, n);
      io->recv_data(bits.get(), n);
    } else {
      for(int i = 0; i < n; ++i) {
        bits[i] = getLSB(data[i]);
      }
      ccrh.Hn(pre_data.data(), data.data(), 0, n);
      for (int i = 0; i < n; ++i) {
        bits[i] = (b[i] != bits[i]);
      }
      io->send_data(bits.get(), n);
    }
    return { std::move(pre_data), std::move(bits) };
  }
};

}
#endif// _PRE_OT__
