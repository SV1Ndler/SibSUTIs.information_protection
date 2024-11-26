#include <algorithm>
#include <crypto-utils.hpp>
#include <utility>

namespace crypto {

unsigned long fast_exp(unsigned long a, unsigned long x, unsigned long p) {
  unsigned long long y = 1;
  unsigned long long s = a;

  for (; x > 0; x >>= 1) {
    if ((x & 1) == 1) {
      y = (y * s) % p;
    }
    s = (s * s) % p;
  }

  return static_cast<unsigned long>(y);
}

ExtendedGcdResult extended_gcd(long a, long b) {
  if (a < b) {
    auto result = extended_gcd(b, a);

    return {result.gcd(), result.y(), result.x()};
  }

  std::array<long, 3> U = {a, 1, 0};
  std::array<long, 3> V = {b, 0, 1};

  while (V[0] != 0) {
    auto q = U[0] / V[0];
    std::array<long, 3> T = {U[0] % V[0], U[1] - q * V[1],
                                          U[2] - q * V[2]};

    U = V;
    V = T;
  }

  return U;
}

long get_dlog_DS(long a, long y, long p) {
  struct val_with_idx {
    val_with_idx(long val, long idx)
     : val{val}, idx{idx} {}

    long val;
    long idx;
  };


  long m = std::max(p >> 1, 3L);
  long k = m;

  const long y_mod_p = y % p;
  const long a_mod_p = a % p;
  std::vector<val_with_idx> v_m;
  v_m.reserve(m);
  v_m.push_back(val_with_idx(y_mod_p, 0));
  long a_tmp = 1;
  for (long i = 1; i <= m - 1; ++i) {
    a_tmp = (a_tmp * (a_mod_p)) % p;
    v_m.push_back(val_with_idx((y_mod_p * a_tmp) % p, i)); //static_cast<unsigned long long>(y)
  }

  const long a_pow_m = fast_exp(a, m, p);
  std::vector<val_with_idx> v_k;
  v_k.reserve(k);
  v_k.push_back(val_with_idx(a_pow_m, 1));
  a_tmp = a_pow_m;
  for (long i = 2; i <= k; ++i) {
    a_tmp = (a_tmp * a_pow_m) % p;
    v_k.push_back(val_with_idx(a_tmp, i));
  }


  auto sort_func = [](val_with_idx a, val_with_idx b) {
    return a.val < b.val;
  };
  std::sort(v_m.begin(), v_m.end(), sort_func);
  std::sort(v_k.begin(), v_k.end(), sort_func);

  long v_m_idx = 0, v_k_idx = 0; // v_k_idx - i, v_m_idx - j
  while(v_m[v_m_idx].val != v_k[v_k_idx].val) {
    if(v_m[v_m_idx].val < v_k[v_k_idx].val){
      ++v_m_idx;
    } else {
      ++v_k_idx;
    }
  }

  return v_k[v_k_idx].idx * m - v_m[v_m_idx].idx;
}

} // namespace crypto