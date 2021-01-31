#ifndef BASE_OT_H__
#define BASE_OT_H__

#include "link.h"

#include <bitset>

namespace BaseOT {

std::pair<
  std::vector<std::bitset<128>>,
  std::vector<std::bitset<128>>>
send(Link&);

std::vector<std::bitset<128>> recv(Link&, const std::bitset<128>&);

}

#endif
