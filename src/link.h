#ifndef LINK_H__
#define LINK_H__


#include <cstdint>
#include <span>

#include <emp-tool/emp-tool.h>


struct Link {
  virtual void send(std::span<const std::byte>) = 0;
  virtual void recv(std::span<std::byte>) = 0;
  virtual void flush() = 0;
  virtual ~Link() { }

  void send(const std::byte* bytes, std::size_t n) {
    send(std::span<const std::byte> { bytes, n });
  }

  void recv(std::byte* bytes, std::size_t n) {
    recv(std::span<std::byte> { bytes, n });
  }
};


struct NetLink : public Link {
public:
  NetLink() { }
  NetLink(emp::NetIO* io) : io(io) { }

  void send(std::span<const std::byte> s) {
    io->send_data(s.data(), s.size());
  }

  void recv(std::span<std::byte> s) {
    io->recv_data(s.data(), s.size());
  }

  void flush() {
    io->flush();
  }

private:
  emp::NetIO* io;
};


#endif
