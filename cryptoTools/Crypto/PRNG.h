#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/AES.h>
#include <vector>
#include <cstring>
#include <cryptoTools/Common/Aligned.h>

namespace osuCrypto
{

    // A Peudorandom number generator implemented using AES-NI.
    class PRNG
    {
    public:
        // default construct leaves the PRNG in an invalid state.
        // SetSeed(...) must be called before get(...)
        // 创建一个无效的 PRNG，必须调用 SetSeed(...) 函数设置种子
        PRNG() = default;

        // explicit constructor to initialize the PRNG with the
        // given seed and to buffer bufferSize number of AES block
        // 显式构造函数，使用提供的种子和缓冲区大小初始化PRNG
        PRNG(const block &seed, u64 bufferSize = 256);

        // standard move constructor. The moved from PRNG is invalid
        // unless SetSeed(...) is called.
        // 移动构造函数，移动后是无效的，需要重新调用SetSeed(...)
        PRNG(PRNG &&s);

        // Copy is not allowed.
        // 不允许复制构造函数
        PRNG(const PRNG &) = delete;

        // standard move assignment. The moved from PRNG is invalid
        // unless SetSeed(...) is called.
        // 移动赋值运算符，移动后是无效的，需要重新调用SetSeed(...)
        void operator=(PRNG &&);

        // Set seed from a block and set the desired buffer size.
        // 设置种子和缓冲区大小，默认大小为256
        void SetSeed(const block &b, u64 bufferSize = 256);

        // Return the seed for this PRNG.
        // 获取 PRNG 的种子
        const block getSeed() const;

        // template<typename T, typename = void>
        // struct has_randomize_member_func : std::false_type
        //{};

        // template <typename T>
        // struct has_randomize_member_func < T, std::void_t<

        //    // must have a randomize(PRNG&) member fn
        //    decltype(std::declval<T>().randomize(std::declval<PRNG&>()))

        //    >>
        //    : std::true_type{};

        struct Any
        {
            PRNG &mPrng;

            template <typename T, typename U = typename std::enable_if<
                                      std::is_standard_layout<T>::value &&
                                          std::is_trivial<T>::value,
                                      T>::type>
            operator T()
            {
                return mPrng.get<T>();
            }
        };

        Any get()
        {
            return {*this};
        }

        // Templated function that returns the a random element
        // of the given type T.
        // Required: T must be a POD type.
        // 用于从 PRNG 对象中获取一个随机生成的指定类型 T 的元素
        template <typename T>
        typename std::enable_if<
            std::is_standard_layout<T>::value &&
                std::is_trivial<T>::value,
            T>::type
        get()
        {
            T ret;
            if (mBufferByteCapacity - mBytesIdx >= sizeof(T))
            {
                memcpy(&ret, ((u8 *)mBuffer.data()) + mBytesIdx, sizeof(T));
                mBytesIdx += sizeof(T);
            }
            else
                get(&ret, 1);

            return ret;
        }

        // Templated function that fills the provided buffer
        // with random elements of the given type T.
        // Required: T must be a POD type.
        // 获取指定数量的随机生成的类型为 T 的元素，并将它们填充到指定的缓冲区中
        template <typename T>
        typename std::enable_if<
            std::is_standard_layout<T>::value &&
                std::is_trivial<T>::value,
            void>::type
        get(T *dest, u64 length)
        {
            u64 lengthu8 = length * sizeof(T);
            u8 *destu8 = (u8 *)dest;

            implGet(destu8, lengthu8);
        }

        void implGet(u8 *datau8, u64 lengthu8);

        // Templated function that fills the provided buffer
        // with random elements of the given type T.
        // Required: T must be a POD type.
        // 填充提供的 span<T> 对象 dest，其中包含随机的 POD 类型元素
        template <typename T>
        typename std::enable_if<
            std::is_standard_layout<T>::value &&
                std::is_trivial<T>::value,
            void>::type
        get(span<T> dest)
        {
            get(dest.data(), dest.size());
        }

        // returns the buffer of maximum maxSize bytes or however
        // many the internal buffer has, which ever is smaller. The
        // returned bytes are "consumed" and will not be used on
        // later calls to get*(...). Note, buffer may be invalidated
        // on the next call to get*(...) or destruction.
        // 返回一个 span<u8> 对象，其中包含最多 maxSize 字节的随机数据
        // 这些数据在后续的调用中将被使用，并且可能在下一次调用或销毁时失效
        // 需要注意的是，在下一次对 get*() 的调用或对象销毁时，缓冲区可能会失效
        span<u8> getBufferSpan(u64 maxSize)
        {
            if (mBytesIdx == mBufferByteCapacity)
                refillBuffer();

            auto data = ((u8 *)mBuffer.data()) + mBytesIdx;
            auto size = std::min(maxSize, mBufferByteCapacity - mBytesIdx);

            mBytesIdx += size;

            return span<u8>(data, size);
        }

        // Returns a random element from {0,1}
        u8 getBit();

        // STL random number interface
        typedef u64 result_type;
        static constexpr result_type min() { return 0; }
        static constexpr result_type max() { return (result_type)-1; }
        result_type operator()()
        {
            return get<result_type>();
        }

        template <typename R>
        R operator()(R mod)
        {
            // typename std::make_unsigned<R>::type 表示将类型 R 转换为其无符号整数版本的结果类型
            return get<typename std::make_unsigned<R>::type>() % mod;
        }

        // internal buffer to store future random values.
        AlignedUnVector<block> mBuffer;

        // AES that generates the randomness by computing AES_seed({0,1,2,...})
        AES mAes;

        // Indicators denoting the current state of the buffer.
        u64 mBytesIdx = 0,
            mBlockIdx = 0,
            mBufferByteCapacity = 0;

        // refills the internal buffer with fresh randomness
        void refillBuffer();

        PRNG fork()
        {
            return PRNG(get<block>());
        }
    };

    // specialization to make bool work correctly.
    template <>
    inline void PRNG::get<bool>(bool *dest, u64 length)
    {
        get((u8 *)dest, length);
        for (u64 i = 0; i < length; ++i)
            dest[i] = ((u8 *)dest)[i] & 1;
    }

    // specialization to make bool work correctly.
    template <>
    inline bool PRNG::get<bool>()
    {
        u8 ret;
        get((u8 *)&ret, 1);
        return ret & 1;
    }

}
