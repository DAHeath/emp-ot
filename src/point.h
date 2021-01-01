#ifndef OT_POINT_H__
#define OT_POINT_H__

#include "link.h"

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <memory>
#include <vector>
#include <bitset>

struct BigInt {
  BigInt(BIGNUM* ptr) : ptr(ptr) { }
  BigInt();
  BigInt(const BigInt&);
  BigInt& operator=(const BigInt&);
  BigInt(BigInt&&) noexcept;
  BigInt& operator=(BigInt&&);
  ~BigInt();

  BIGNUM* operator*() { return ptr; }
  const BIGNUM* operator*() const { return ptr; }

  BIGNUM* ptr = nullptr;
};


struct Group;


struct Point {
  Point() { }
  Point(const Group&);
  Point(const Point&);
  Point& operator=(const Point&);
  Point(Point&&);
  Point& operator=(Point&&);
  ~Point();

  [[nodiscard]] size_t size() const;
  [[nodiscard]] static Point fromBin(Group&, std::span<const std::byte>);
  void toBin(char*, size_t) const;

  [[nodiscard]] Point operator+(const Point&) const;
  [[nodiscard]] Point operator*(const BigInt&) const;
  Point operator~() const;

  void write(Link&) const;
  [[nodiscard]] static Point read(Group&, Link&);
  std::bitset<128> hash(uint64_t) const;

  EC_POINT *point = nullptr;
  const Group* group = nullptr;
};


struct Group {
  Group();
  [[nodiscard]] BigInt randBigInt();
  [[nodiscard]] Point operator*(const BigInt&) const;

  std::unique_ptr<EC_GROUP, void(*)(EC_GROUP*)> ec_group;
  std::unique_ptr<BN_CTX, void(*)(BN_CTX*)> bn_ctx;
  BigInt order;
};

#endif
