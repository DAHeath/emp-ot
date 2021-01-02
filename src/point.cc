#include "point.h"
#include "gthash.h"
#include <openssl/obj_mac.h>
#include <iostream>


inline void error(const char * s, int line = 0, const char * file = nullptr) {
  fprintf(stderr, s, "\n");
  if (file != nullptr) {
    fprintf(stderr, "at %d, %s\n", line, file);
  }
  exit(1);
}


BigInt::BigInt() : ptr(BN_new()) { }


BigInt::BigInt(const BigInt& o) : ptr(BN_new()) {
  BN_copy(ptr, o.ptr);
}


BigInt& BigInt::operator=(const BigInt& o) {
  BN_copy(ptr, o.ptr);
  return *this;
}


BigInt::BigInt(BigInt&& o) noexcept {
  ptr = o.ptr;
  o.ptr = nullptr;
}


BigInt& BigInt::operator=(BigInt&& o){
  if (ptr != nullptr) {
    BN_free(ptr);
  }
  ptr = o.ptr;
  o.ptr = nullptr;
  return *this;
}


BigInt::~BigInt() {
  if (ptr != nullptr) {
    BN_free(ptr);
  }
}


Point::Point(const Group& g) : group(&g) {
  point = EC_POINT_new(&*g.ec_group);
}


Point::Point(const Point& p) {
  group = p.group;
  if (group != nullptr) {
    point = EC_POINT_new(&*group->ec_group);
    int ret = EC_POINT_copy(point, p.point);
    if (ret == 0) {
      error("ECC COPY");
    }
  }
}

Point& Point::operator=(const Point& p) {
  if (point != nullptr) {
    EC_POINT_free(point);
  }
  group = p.group;
  if (group != nullptr) {
    point = EC_POINT_new(&*group->ec_group);
    int ret = EC_POINT_copy(point, p.point);
    if (ret == 0) {
      error("ECC COPY");
    }
  }
  return *this;
}

Point::Point(Point&& p) {
  group = p.group;
  point = p.point;
  p.point = nullptr;
  p.group = nullptr;
}

Point& Point::operator=(Point&& p) {
  if (point != nullptr) {
    EC_POINT_free(point);
  }
  group = p.group;
  point = p.point;
  p.point = nullptr;
  p.group = nullptr;
  return *this;
}

Point::~Point() {
  if (point != nullptr) {
    EC_POINT_free(point);
  }
}


void Point::toBin(std::span<std::byte> buf) const {
  int ret = EC_POINT_point2oct(
      &*group->ec_group,
      point,
      POINT_CONVERSION_UNCOMPRESSED,
      (unsigned char*) buf.data(),
      buf.size(),
      &*group->bn_ctx);
  if (ret == 0) {
    error("ECC TO_BIN");
  }
}


size_t Point::size() const {
  size_t ret = EC_POINT_point2oct(
      &*group->ec_group,
      point,
      POINT_CONVERSION_UNCOMPRESSED,
      NULL,
      0,
      &*group->bn_ctx);
  if(ret == 0) error("ECC SIZE_BIN");
  return ret;
}

Point Point::fromBin(Group& g, std::span<const std::byte> buf) {
  Point out;
  out.group = &g;
  out.point = EC_POINT_new(&*g.ec_group);

  int ret = EC_POINT_oct2point(
      &*g.ec_group,
      out.point,
      (unsigned char*)buf.data(),
      buf.size(),
      &*g.bn_ctx);

  if (ret == 0) {
    error("ECC FROM_BIN");
  }
  return out;
}


Point Point::operator+(const Point& rhs) const {
  Point ret(*group);
  int res = EC_POINT_add(&*group->ec_group, ret.point, point, rhs.point, &*group->bn_ctx);
  if(res == 0) {
    error("ECC ADD");
  }
  return ret;
}


Point Point::operator*(const BigInt &m) const {
  Point ret(*group);
  int res = EC_POINT_mul(&*group->ec_group, ret.point, NULL, point, *m, &*group->bn_ctx);
  if(res == 0) {
    error("ECC MUL");
  }
  return ret;
}


Point Point::operator~() const {
  Point ret (*this);
  int res = EC_POINT_invert(&*group->ec_group, ret.point, &*group->bn_ctx);
  if (res == 0) {
    error("ECC INV");
  }
  return ret;
}


void Point::write(Link& link) const {
  const size_t n = size();
  link.send((const std::byte*)&n, 4);
  std::vector<std::byte> scratch(n);
  toBin(scratch);
  link.send(scratch);
}


Point Point::read(Group& g, Link& link) {
  size_t n = 0;
  link.recv((std::byte*)&n, 4);
  std::vector<std::byte> scratch(n);
  link.recv(scratch.data(), n);
  return Point::fromBin(g, scratch);
}


std::bitset<128> Point::hash(uint64_t id) const {
  size_t n = size();
  std::vector<std::byte> buf(n+8);
  std::span<std::byte> scratch(buf);
  toBin(scratch.subspan(0, n));
  memcpy(scratch.subspan(n).data(), &id, 8);
  return ::hash(scratch.data(), n+8);
}


Group::Group()
  : ec_group (
      EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), // NIST P-256
      EC_GROUP_free),
    bn_ctx (BN_CTX_new(), BN_CTX_free) {
  EC_GROUP_precompute_mult(&*ec_group, &*bn_ctx);
  EC_GROUP_get_order(&*ec_group, *order, &*bn_ctx);
}

BigInt Group::randBigInt() {
  BigInt n;
  BN_rand_range(*n, *order);
  return n;
}


Point Group::operator*(const BigInt& m) const {
  Point res(*this);
  int ret = EC_POINT_mul(&*ec_group, res.point, *m, NULL, NULL, &*bn_ctx);
  if(ret == 0) {
    error("ECC GEN MUL");
  }
  return res;
}
