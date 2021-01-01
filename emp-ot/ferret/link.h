#ifndef LINK_H__
#define LINK_H__


#include <cstdint>
#include <span>


using byte = std::uint8_t;


struct Link {
  virtual void send(std::span<const byte>) = 0;
  virtual void recv(std::span<byte>) = 0;
  virtual void flush() = 0;
};


#endif
