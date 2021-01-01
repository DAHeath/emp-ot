#ifndef BASE_OT_H__
#define BASE_OT_H__

#include <iostream>
#include <bitset>

namespace BaseOT {

std::pair<std::vector<std::bitset<128>>, std::vector<std::bitset<128>>> send(std::iostream&);
std::pair<std::bitset<128>, std::vector<std::bitset<128>>> recv(std::iostream&);

}

#endif
