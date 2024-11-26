#include <gtest/gtest.h>
#include<crypto-utils.hpp>
#include<string>

void check_extended_gcd(long a, long b, crypto::ExtendedGcdResult result) {
    long max_gcd = 1;
    for(long i = 2; i <= a && i <= b; ++i) {
        if(a % i == 0 && b % i == 0) {
            max_gcd = i;
        }
    }

    ASSERT_EQ(result.gcd(), max_gcd);
    ASSERT_EQ(a*result.x() + b*result.y(), result.gcd());
}

TEST(FastExp, MainCases01) {
     for(unsigned long a = 2; a <= 10; ++a) {
        for(unsigned long p = 2; p <= 10; ++p) {
            const unsigned long a_mod_p = a % p;
            unsigned long correct_result = a_mod_p;

            for(unsigned long x = 2; x <= 10; ++x) {
                correct_result = (correct_result * a_mod_p) % p;
                const std::string info = "a = " + std::to_string(a) +
                                         ", x = " + std::to_string(x) +
                                         ", p = " + std::to_string(p); 

                SCOPED_TRACE(info.c_str());
                EXPECT_EQ(crypto::fast_exp(a, x, p), correct_result);
            }       
        }
     }
}

TEST(FastExp, EdgeCases01) {
    {
        SCOPED_TRACE("");
        const unsigned long a = 1;
        const unsigned long x = 10;
        const unsigned long p = 2;
        const unsigned long correct_result = 1;

        EXPECT_EQ(crypto::fast_exp(a, x, p), correct_result);
    }
    {
        SCOPED_TRACE("");
        const unsigned long a = 1;
        const unsigned long x = 99;
        const unsigned long p = 15;
        const unsigned long correct_result = 1;

        EXPECT_EQ(crypto::fast_exp(a, x, p), correct_result);
    }
    {
        SCOPED_TRACE("");
        const unsigned long a = 10;
        const unsigned long x = 1;
        const unsigned long p = 15;
        const unsigned long correct_result = 10;

        EXPECT_EQ(crypto::fast_exp(a, x, p), correct_result);
    }
    {
        SCOPED_TRACE("");
        const unsigned long a = 10;
        const unsigned long x = 1;
        const unsigned long p = 6;
        const unsigned long correct_result = 4;

        EXPECT_EQ(crypto::fast_exp(a, x, p), correct_result);
    }
    {
        SCOPED_TRACE("");
        const unsigned long a = 10;
        const unsigned long x = 2;
        const unsigned long p = 5;
        const unsigned long correct_result = 0;

        EXPECT_EQ(crypto::fast_exp(a, x, p), correct_result);
    }
    {
        SCOPED_TRACE("");
        const unsigned long a = 10;
        const unsigned long x = 32;
        const unsigned long p = 1;
        const unsigned long correct_result = 0;

        EXPECT_EQ(crypto::fast_exp(a, x, p), correct_result);
    }
}

TEST(EeAlgo, MainCases01) {
    for(unsigned long a = 2; a <= 100; ++a) {
        for(unsigned long b = 2; b <= 100; ++b) {
            auto result = crypto::extended_gcd(a, b);
            std::string info = "a = " + std::to_string(a) +
                               " , b = " + std::to_string(b) +
                               " , x = " + std::to_string(result.x()) +
                               " , y = " + std::to_string(result.y());

            SCOPED_TRACE(info);
            check_extended_gcd(a, b, result);
        }
    }
}

TEST(CreateSharedSecretKeyDh, MainCase01) {
    const long s = 2;
    const long g = 5;
    const long p = 23;

    const long X1 = 6;
    const long X2 = 15;

    const long Y1 = crypto::fast_exp(g, X1, p);
    const long Y2 = crypto::fast_exp(g, X2, p);

    const long Z12 = crypto::create_shared_secret_key_DH(Y2, X1, p);
    const long Z21 = crypto::create_shared_secret_key_DH(Y1, X2, p);

    EXPECT_EQ(Y1, 8);
    EXPECT_EQ(Y2, 19);
    EXPECT_EQ(Z12, Z21);
    EXPECT_EQ(Z12, s);
}

TEST(GetDlogDs, MainCase01) {
    {
        SCOPED_TRACE("");
        const long a = 2;
        const long x_correct = 5;
        const long p = 23;

        const long y_correct = 9;
        const long y = crypto::fast_exp(a, x_correct, p); 

        const long x = crypto::get_dlog_DS(a, y, p);

        EXPECT_EQ(y, y_correct);
        EXPECT_EQ(crypto::fast_exp(a, x, p), y);
        EXPECT_EQ(x, x_correct);
    }

    {
        SCOPED_TRACE("");
        const long a = 5;
        const long x_correct = 7;
        const long p = 17;
        const long y = crypto::fast_exp(a, x_correct, p); 

        const long x = crypto::get_dlog_DS(a, y, p);

        EXPECT_EQ(crypto::fast_exp(a, x, p), y);
        EXPECT_EQ(x, x_correct);
    }
}