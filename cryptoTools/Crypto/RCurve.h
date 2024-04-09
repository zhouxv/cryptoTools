#pragma once

#include <cryptoTools/Common/Defines.h>

#ifdef ENABLE_RELIC

#include <string.h>
extern "C"
{
#include <relic/relic_bn.h>
#include <relic/relic_ep.h>
}
#ifdef MONTY
#undef MONTY
#endif
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include "Hashable.h"

#ifndef RLC_FP_BYTES
#define RLC_FP_BYTES FP_BYTES
#endif

namespace osuCrypto
{

    class REllipticCurve;
    class REccPoint;
    class EccBrick;

    class REccNumber
    {
    public:
        //  默认构造函数
        REccNumber();

        // 拷贝构造函数
        REccNumber(const REccNumber &num);

        // 移动构造函数
        REccNumber(REccNumber &&moveFrom)
        {
            memcpy(&mVal, &moveFrom.mVal, sizeof(bn_t));
            bn_null(moveFrom.mVal);
        }

        // 构造函数，使用给定的PRNG从随机数初始化对象
        REccNumber(PRNG &prng);

        // 构造函数，使用给定的i32值初始化对象
        REccNumber(const i32 &val);

        // backwards compatible constructors
        REccNumber(REllipticCurve &);
        REccNumber(REllipticCurve &, const REccNumber &num);
        REccNumber(REllipticCurve &, PRNG &prng);
        REccNumber(REllipticCurve &, const i32 &val);

        ~REccNumber();

        REccNumber &operator=(const REccNumber &c);
        REccNumber &operator=(REccNumber &&moveFrom)
        {
            std::swap(mVal, moveFrom.mVal);
            return *this;
        }

        REccNumber &operator=(const bn_t c);
        REccNumber &operator=(int i);

        REccNumber &operator++();
        REccNumber &operator--();
        REccNumber &operator+=(int i);
        REccNumber &operator-=(int i);
        REccNumber &operator+=(const REccNumber &b);
        REccNumber &operator-=(const REccNumber &b);
        REccNumber &operator*=(const REccNumber &b);
        REccNumber &operator*=(int i);
        REccNumber &operator/=(const REccNumber &b);
        REccNumber &operator/=(int i);
        // void inplaceNegate();

        // 获取当前 REccNumber 对象的负值
        REccNumber negate() const;

        // 获取当前 REccNumber 对象的模反元素
        // (a * b) mod m = 1，a 为 b 在模 m 下的模反元素
        REccNumber inverse() const;

        bool operator==(const REccNumber &cmp) const;
        bool operator==(const int &cmp) const;
        friend bool operator==(const int &cmp1, const REccNumber &cmp2);
        bool operator!=(const REccNumber &cmp) const;
        bool operator!=(const int &cmp) const;
        friend bool operator!=(const int &cmp1, const REccNumber &cmp2);

        bool operator>=(const REccNumber &cmp) const;
        bool operator>=(const int &cmp) const;

        bool operator<=(const REccNumber &cmp) const;
        bool operator<=(const int &cmp) const;

        bool operator>(const REccNumber &cmp) const;
        bool operator>(const int &cmp) const;

        bool operator<(const REccNumber &cmp) const;
        bool operator<(const int &cmp) const;

        // 检查当前大整数是否为素数
        bool isPrime() const;
        // 检查当前大整数是否为零
        bool iszero() const;

        // const REccNumber& modulus() const;

        friend REccNumber operator-(const REccNumber &);
        friend REccNumber operator+(const REccNumber &, int);
        friend REccNumber operator+(int, const REccNumber &);
        friend REccNumber operator+(const REccNumber &, const REccNumber &);

        friend REccNumber operator-(const REccNumber &, int);
        friend REccNumber operator-(int, const REccNumber &);
        friend REccNumber operator-(const REccNumber &, const REccNumber &);

        friend REccNumber operator*(const REccNumber &, int);
        friend REccNumber operator*(int, const REccNumber &);
        friend REccNumber operator*(const REccNumber &, const REccNumber &);

        friend REccNumber operator/(const REccNumber &, int);
        friend REccNumber operator/(int, const REccNumber &);
        friend REccNumber operator/(const REccNumber &, const REccNumber &);

        friend REccNumber operator^(const REccNumber &base, const REccNumber &exp);

        // 返回 REccNumber 的十进制表示的位数
        u64 sizeDigits() const;
        // 返回 REccNumber 的字节大小
        u64 sizeBytes() const;
        // 将 REccNumber 转换为二进制格式并写入到提供的目标缓冲区中
        void toBytes(u8 *dest) const;
        // 从二进制格式的源数据中读取并设置 REccNumber 的值
        void fromBytes(const u8 *src);
        // 从十六进制格式的源字符串中读取并设置 REccNumber 的值
        void fromHex(const char *src);
        // void fromDec(const char* src);

        // 使用给定的伪随机数生成器 PRNG 生成随机的 REccNumber
        void randomize(PRNG &prng);

        // 使用给定的种子生成一个新的伪随机数生成器 PRNG
        // 调用 randomize(PRNG &prng) 方法生成随机的大整数值
        void randomize(const block &seed);

        operator bn_t &()
        {
            return mVal;
        }
        operator const bn_t &() const { return mVal; }

    private:
        void init();
        void reduce();

        const bn_st *modulus() const;

    public:
        // bn_t 表示大整数
        bn_t mVal;

        friend class REllipticCurve;
        friend REccPoint;
        friend std::ostream &operator<<(std::ostream &out, const REccNumber &val);
    };

    // 重载的输出流运算符，用于将 REccPoint 类型的对象打印到输出流中
    // 将 REccNumber 对象以十六进制格式打印到输出流中
    std::ostream &operator<<(std::ostream &out, const REccNumber &val);

    class REccPoint
    {
    public:
        // 默认构造函数，创建一个空的椭圆曲线点
        REccPoint() { ep_new(mVal); };

        // 接受一个伪随机数生成器对象作为参数的构造函数，用于生成一个随机的椭圆曲线点
        REccPoint(PRNG &prng)
        {
            ep_new(mVal);
            randomize(prng);
        }

        // 拷贝构造函数，从另一个椭圆曲线点对象复制数据以创建新的对象
        REccPoint(const REccPoint &copy)
        {
            ep_new(mVal);
            ep_copy(*this, copy);
        }

        // 移动构造函数，从另一个椭圆曲线点对象移动数据以创建新的对象
        REccPoint(REccPoint &&moveFrom)
        {
            memcpy(&mVal, &moveFrom.mVal, sizeof(ep_t));
            ep_null(moveFrom.mVal);
        }

        // backwards compatible constructors
        REccPoint(REllipticCurve &) { ep_new(mVal); };
        REccPoint(REllipticCurve &, const REccPoint &copy)
        {
            ep_new(mVal);
            ep_copy(*this, copy);
        }

        ~REccPoint() { ep_free(mVal); }

        REccPoint &operator=(const REccPoint &copy);
        REccPoint &operator=(REccPoint &&moveFrom)
        {
            std::swap(mVal, moveFrom.mVal);
            return *this;
        }

        REccPoint &operator+=(const REccPoint &addIn);
        REccPoint &operator-=(const REccPoint &subtractIn);
        REccPoint &operator*=(const REccNumber &multIn);

        REccPoint operator+(const REccPoint &addIn) const;
        REccPoint operator-(const REccPoint &subtractIn) const;
        REccPoint operator*(const REccNumber &multIn) const;

        // Multiply a scalar by the generator of the elliptic curve. Unsure if this is the whole
        // curve or a prime order subgroup, but it should be the same as
        // REllipticCurve::getGenerator() * n.
        // 将椭圆曲线的生成元（通常是基点）与一个REccNumber标量相乘，从而生成一个新的椭圆曲线点
        // 乘法运算的结果应该与 REllipticCurve::getGenerator() * n
        // 作者指出了不确定性，即不确定生成元是整个曲线的生成元，还是素数阶子群的生成元
        static REccPoint mulGenerator(const REccNumber &n);
        //

        bool operator==(const REccPoint &cmp) const;
        bool operator!=(const REccPoint &cmp) const;

        // Generate randomly from a 256 bit hash. d must point to fromHashLength uniformly random
        // bytes.
        // 静态方法，从一个256比特的哈希值随机生成一个椭圆曲线点
        static REccPoint fromHash(const unsigned char *d)
        {
            REccPoint p;
            p.fromHash(d, fromHashLength);
            return p;
        }

        // 静态方法，从一个 RandomOracle 随机生成一个椭圆曲线点
        static REccPoint fromHash(RandomOracle ro)
        {
            std::array<unsigned char, fromHashLength> h;
            ro.Final(h);
            return fromHash(h.data());
        }

        // Feed data[0..len] into a hash function, then map the hash to the curve.
        // 接受一个字节序列和其长度作为输入，并将其映射到椭圆曲线上的点
        void fromHash(const unsigned char *data, size_t len);

        // 0x20=32
        static const size_t fromHashLength = 0x20;

        u64 sizeBytes() const { return size; }

        // 当前的椭圆曲线点编码为字节序列
        void toBytes(u8 *dest) const;
        // 从提供的字节序列中读取数据，并将其解码为椭圆曲线点
        void fromBytes(u8 *src);

        // 该函数被用于判断是否为无穷远点
        // 在椭圆曲线上，无穷远点表示曲线上不存在的一个点，它在几何上被视为曲线的“端点”。
        // 在椭圆曲线加法运算中，将一个点与无穷远点相加，结果仍然是该点本身。
        // 因此，无穷远点在椭圆曲线加法中起着类似于零元素的作用。
        bool iszero() const;

        // void fromHex(char* x, char* y);
        // void fromDec(char* x, char* y);
        // void fromNum(REccNumber& x, REccNumber& y);

        // 用指定的伪随机数生成器对象随机化当前椭圆曲线点
        void randomize(PRNG &prng);
        // 使用指定的种子随机化当前椭圆曲线点，
        void randomize(const block &seed);
        // 调用 Relic 库中的 ep_rand 函数生成随机椭圆曲线点
        void randomize();

        // 允许在需要时将 REccPoint 对象用作 ep_t 类型的引用
        operator ep_t &() { return mVal; }
        // 将常量的 REccPoint 对象转换为对应的 ep_t 类型的常量引用
        operator const ep_t &() const { return mVal; }

        // ((int)((256-1)/8+1))+1=32+1=33, NISY-P256 多出来的1字节是eccPoint的编码格式, 紧凑编码
        static const u64 size = RLC_FP_BYTES + 1;

        // ep_t 表示椭圆曲线上的一个点，其中包括该点的坐标以及坐标的表示方式
        ep_t mVal;

    private:
        friend EccBrick;
        friend REccNumber;
        friend std::ostream &operator<<(std::ostream &out, const REccPoint &val);
    };

    // 重载的输出流运算符，用于将 REccPoint 类型的对象打印到输出流中
    // 将 REccPoint 对象的坐标以十六进制格式打印到输出流中
    std::ostream &operator<<(std::ostream &out, const REccPoint &val);

    // class EccBrick
    //{
    // public:
    //     EccBrick(const REccPoint& copy);
    //     EccBrick(EccBrick&& copy);

    //    REccPoint operator*(const REccNumber& multIn) const;

    //    void multiply(const REccNumber& multIn, REccPoint& result) const;

    // private:

    //    ebrick2 mBrick2;
    //    ebrick mBrick;
    //    REllipticCurve* mCurve;

    //};

    // REllipticCurve类
    // 表示一个椭圆曲线
    class REllipticCurve
    {
    public:
        typedef REccPoint Point;

        // 默认为 NIST-P256, 方程为 y^2 = x^3 + ax + b mod q
        REllipticCurve(u64 curveID = 0);

        // 获取椭圆曲线的生成元
        Point getGenerator() const;

        // 获取椭圆曲线的生成元集合，某些椭圆曲线可能有多个生成元
        std::vector<Point> getGenerators() const;

        // 获取椭圆曲线的阶数（Order）。阶数是椭圆曲线上的点的数量，包括无穷远点。
        REccNumber getOrder() const;

        void printCurveParam() const;

    private:
        friend Point;
        friend REccNumber;
    };

    // 模板结构，用于对 REccPoint 进行哈希处理
    template <>
    struct Hashable<REccPoint, void> : std::true_type
    {
        template <typename Hasher>
        static void hash(const REccPoint &p, Hasher &hasher)
        {
            u8 buff[REccPoint::size];
            p.toBytes(buff);
            hasher.Update(buff, REccPoint::size);
        }
    };
}
#endif
