#ifndef INFORMATION_PROTECTION_CRYPTO_HPP_
#define INFORMATION_PROTECTION_CRYPTO_HPP_

#include <array>
#include <vector>
#include <cmath>
#include <stdexcept>
#include <random>

namespace crypto {

struct ExtendedGcdResult {
public:
 ExtendedGcdResult(long gcd, long x, long y):
  arr{gcd, x, y} {}

  ExtendedGcdResult(std::array<long, 3> val):
  arr{val} {}

  long& gcd(){ return arr[0]; }
  long& x(){ return arr[1]; }
  long& y(){ return arr[2]; }

 std::array<long, 3> arr;
};

/** @brief Функция быстрого возведения в степень по модулю. y = a^x mod p
 *  @param a основание степени
 *  @param x показщатель степени
 *  @param p модуль
 */
unsigned long fast_exp(unsigned long a, unsigned long x, unsigned long p);

/** @brief Обобщенный алгоритм Евклида. ax + by = gcd(a, b). (Extended Euclidean algorithm)
 *  
 * @return {gcd(a, b), x, y}
 */
ExtendedGcdResult extended_gcd(long a, long b);

/** @brief Функция построения общего ключа для двух абонентов по схеме Диффи-Хелмлмана
 *  @param y открытый ключ
 *  @param x закрытый ключ
 *  @param p модуль
 */
inline unsigned long create_shared_secret_key_DH(unsigned long y,
                                          unsigned long x,
                                          unsigned long p) {
  return fast_exp(y, x, p);
}

/** @brief Нахождения дискретного лоагрифма методом "Шаг маладенца, шаг великана". x = log<a>(y) mod p
 */
long get_dlog_DS(long a, long y, long p);

} //namespace crypto

#endif  // INFORMATION_PROTECTION_CRYPTO_HPP_