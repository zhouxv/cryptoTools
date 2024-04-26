#pragma once
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Log.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Matrix.h"
#include <atomic>
#include <string.h>

#ifdef ENABLE_SSE
#define LIBDIVIDE_AVX2
#endif

#include "libdivide.h"

namespace osuCrypto
{
    struct Mod
    {
        // libdivide 库中定义的用于无符号 64 位整数除法，可以用于执行除法和模运算
        libdivide::libdivide_u64_t mDiv;
        // 模运算的模数
        u64 mVal;

        Mod() = default;
        Mod(u64 v)
            : mDiv(libdivide::libdivide_u64_gen(v)), mVal(v)
        {
        }

        Mod(const Mod &) = default;
        Mod &operator=(const Mod &o) = default;

#ifdef ENABLE_SSE
        using block256 = __m256i;
        inline block256 my_libdivide_u64_do_vec256(const block256 &x)
        {
            return libdivide::libdivide_u64_do_vec256(x, &mDiv);
        }
#else
        using block256 = std::array<block, 2>;

        inline block256 _mm256_loadu_si256(block256 *p) { return *p; }

        inline block256 my_libdivide_u64_do_vec256(const block256 &x)
        {
            block256 y;
            auto x64 = (u64 *)&x;
            auto y64 = (u64 *)&y;
            for (u64 i = 0; i < 4; ++i)
            {
                y64[i] = libdivide::libdivide_u64_do(x64[i], &mDiv);
            }

            return y;
        }
#endif

        // 计算 val mod mval
        u64 mod(u64 val)
        {
            return val - libdivide::libdivide_u64_do(val, &mDiv) * mVal;
        }

        // 对一个包含32个64位整数的数组进行模运算
        // 函数首先将数组中的数据加载到8个256位整数变量中（每个变量包含4个64位整数）
        // 对每个256位整数变量进行模运算
        // 将结果更新回原始数组中
        inline void mod32(u64 *vals)
        {
            // std::array<u64, 4> temp64;
            // for (u64 i = 0; i < 32; i += 16)
            {
                u64 i = 0;
                block256 row256a = _mm256_loadu_si256((block256 *)&vals[i]);
                block256 row256b = _mm256_loadu_si256((block256 *)&vals[i + 4]);
                block256 row256c = _mm256_loadu_si256((block256 *)&vals[i + 8]);
                block256 row256d = _mm256_loadu_si256((block256 *)&vals[i + 12]);
                block256 row256e = _mm256_loadu_si256((block256 *)&vals[i + 16]);
                block256 row256f = _mm256_loadu_si256((block256 *)&vals[i + 20]);
                block256 row256g = _mm256_loadu_si256((block256 *)&vals[i + 24]);
                block256 row256h = _mm256_loadu_si256((block256 *)&vals[i + 28]);
                auto tempa = my_libdivide_u64_do_vec256(row256a);
                auto tempb = my_libdivide_u64_do_vec256(row256b);
                auto tempc = my_libdivide_u64_do_vec256(row256c);
                auto tempd = my_libdivide_u64_do_vec256(row256d);
                auto tempe = my_libdivide_u64_do_vec256(row256e);
                auto tempf = my_libdivide_u64_do_vec256(row256f);
                auto tempg = my_libdivide_u64_do_vec256(row256g);
                auto temph = my_libdivide_u64_do_vec256(row256h);
                // auto temp = libdivide::libdivide_u64_branchfree_do_vec256(row256, &mDiv);
                auto temp64a = (u64 *)&tempa;
                auto temp64b = (u64 *)&tempb;
                auto temp64c = (u64 *)&tempc;
                auto temp64d = (u64 *)&tempd;
                auto temp64e = (u64 *)&tempe;
                auto temp64f = (u64 *)&tempf;
                auto temp64g = (u64 *)&tempg;
                auto temp64h = (u64 *)&temph;
                vals[i + 0] -= temp64a[0] * mVal;
                vals[i + 1] -= temp64a[1] * mVal;
                vals[i + 2] -= temp64a[2] * mVal;
                vals[i + 3] -= temp64a[3] * mVal;
                vals[i + 4] -= temp64b[0] * mVal;
                vals[i + 5] -= temp64b[1] * mVal;
                vals[i + 6] -= temp64b[2] * mVal;
                vals[i + 7] -= temp64b[3] * mVal;
                vals[i + 8] -= temp64c[0] * mVal;
                vals[i + 9] -= temp64c[1] * mVal;
                vals[i + 10] -= temp64c[2] * mVal;
                vals[i + 11] -= temp64c[3] * mVal;
                vals[i + 12] -= temp64d[0] * mVal;
                vals[i + 13] -= temp64d[1] * mVal;
                vals[i + 14] -= temp64d[2] * mVal;
                vals[i + 15] -= temp64d[3] * mVal;
                vals[i + 16] -= temp64e[0] * mVal;
                vals[i + 17] -= temp64e[1] * mVal;
                vals[i + 18] -= temp64e[2] * mVal;
                vals[i + 19] -= temp64e[3] * mVal;
                vals[i + 20] -= temp64f[0] * mVal;
                vals[i + 21] -= temp64f[1] * mVal;
                vals[i + 22] -= temp64f[2] * mVal;
                vals[i + 23] -= temp64f[3] * mVal;
                vals[i + 24] -= temp64g[0] * mVal;
                vals[i + 25] -= temp64g[1] * mVal;
                vals[i + 26] -= temp64g[2] * mVal;
                vals[i + 27] -= temp64g[3] * mVal;
                vals[i + 28] -= temp64h[0] * mVal;
                vals[i + 29] -= temp64h[1] * mVal;
                vals[i + 30] -= temp64h[2] * mVal;
                vals[i + 31] -= temp64h[3] * mVal;
            }
        }
    };

    // The parameters that define a cuckoo table.
    // stashSize、scaler、numHash、setSize
    // 存储 CuckooHash 的参数——stashSize、scaler、numHash、setSize
    struct CuckooParam
    {
        u64 mStashSize;
        double mBinScaler;
        u64 mNumHashes, mN;

        // 返回bins的数量
        u64 numBins() { return std::max<u64>(mNumHashes, static_cast<u64>(mN * mBinScaler)); }

        // 创建一个掩码，可以在后续的位运算中用于只保留哈希结果的低位，以便将哈希结果映射到哈希表的索引范围内
        // ull 为 64 位 unsigned long long
        // 1 左移 log2ceil(numBins()) 位，-1 后得到低 log2ceil(numBins()) 均为 1 的掩码
        u64 binMask() { return (1ull << log2ceil(numBins())) - 1; }
    };

    // extern 是 C / C++ 中的一个关键字，用于声明一个外部变量或者函数
    extern CuckooParam k2n32s40CuckooParam;
    extern CuckooParam k2n30s40CuckooParam;
    extern CuckooParam k2n28s40CuckooParam;
    extern CuckooParam k2n24s40CuckooParam;
    extern CuckooParam k2n20s40CuckooParam;
    extern CuckooParam k2n16s40CuckooParam;
    extern CuckooParam k2n12s40CuckooParam;
    extern CuckooParam k2n08s40CuckooParam;
    extern CuckooParam k2n07s40CuckooParam;
    extern CuckooParam k2n06s40CuckooParam;
    extern CuckooParam k2n05s40CuckooParam;
    extern CuckooParam k2n04s40CuckooParam;
    extern CuckooParam k2n03s40CuckooParam;
    extern CuckooParam k2n02s40CuckooParam;
    extern CuckooParam k2n01s40CuckooParam;

    // Two variants of the Cuckoo implementation.
    // Cuckoo 的两种实现，线程安全和线程不安全
    enum CuckooTypes
    {
        ThreadSafe,
        NotThreadSafe
    };

    // Two variants of the Cuckoo values.
    template <CuckooTypes M>
    struct CuckooStorage;

    // Thread safe version requires atomic u64
    // 线程安全版本的CuckooStorage，atomic u64
    template <>
    struct CuckooStorage<ThreadSafe>
    {
        std::atomic<u64> mVal;
    };

    // Not Thread safe version only requires u64.
    // 非线程安全版本的CuckooStorage，u64
    template <>
    struct CuckooStorage<NotThreadSafe>
    {
        u64 mVal;
    };

    // A cuckoo hashing implementation. The cuckoo hash table takes {value, index}
    // pairs as input and stores the index.
    template <CuckooTypes Mode = ThreadSafe>
    class CuckooIndex
    {

    public:
        CuckooIndex();
        ~CuckooIndex();

        // the maximum number of hash functions that are allowed.
#define CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT 3

        struct Bin
        {
            // 64 位，高8位为 hashIdx ，低56位为 idx
            CuckooStorage<Mode> mS;

            // 默认初始化函数，将 CuckooStorage 的 mVal 设置为-1
            Bin()
            {
                mS.mVal = (-1);
            }

            // 将 hashIdx 左移了 56 位，然后与 idx 进行按位或操作
            Bin(u64 idx, u64 hashIdx)
            {
                mS.mVal = (idx | (hashIdx << 56));
            }

            // 拷贝构造函数
            Bin(const Bin &b)
            {
                mS.mVal = (b.load());
            }

            // 判断当前 Bin 是否为空
            bool isEmpty() const
            {
                return load() == u64(-1);
            }

            // 返回 idx
            u64 idx() const
            {
                return load() & (u64(-1) >> 8);
            }

            // 返回 hashIdx
            u64 hashIdx() const
            {
                return load() >> 56;
            }

            // 原子交换 Bin 对象的值
            // 根据 CuckooTypes 调用 exchange 函数
            void swap(u64 &idx, u64 &hashIdx)
            {
                u64 newVal = idx | (hashIdx << 56);
                auto oldVal = exchange(newVal);
                idx = oldVal & (u64(-1) >> 8);
                hashIdx = (oldVal >> 56);
            }

            // 原子地交换 Bin 对象的值（线程安全的实现）
            // 赋新值, 返回旧值
            template <CuckooTypes M = Mode>
            typename std::enable_if<M == ThreadSafe, u64>::type exchange(u64 newVal)
            {
                return mS.mVal.exchange(newVal, std::memory_order_relaxed);
            }

            // 在 ThreadSafe 的情况下
            // 使用了 std::atomic 类型的 load 函数来获取 mS.mVal 的值
            // 指定了 std::memory_order_relaxed 内存顺序，表示没有同步或者排序约束
            template <CuckooTypes M = Mode>
            typename std::enable_if<M == ThreadSafe, u64>::type load() const
            {
                return mS.mVal.load(std::memory_order_relaxed);
            }

            // 原子地交换 Bin 对象的值（非线程安全的实现）
            // 赋新值, 返回旧值
            template <CuckooTypes M = Mode>
            typename std::enable_if<M == NotThreadSafe, u64>::type exchange(u64 newVal)
            {
                auto v = mS.mVal;
                mS.mVal = newVal;
                return v;
            }

            // 在 NotThreadSafe 的情况下，直接返回 mS.mVal
            // 因为在非线程安全的情况下不需要使用原子操作
            template <CuckooTypes M = Mode>
            typename std::enable_if<M == NotThreadSafe, u64>::type load() const
            {
                return mS.mVal;
            }
        };

        // 重插入的限制次数
        u64 mReinsertLimit = 200;
        // 桶的数量和对应的计算掩码
        u64 mNumBins, mNumBinMask;

        // std::vector<u8> mRandHashIdx;
        // PRNG mPrng;

        // cuckooHash 的设置参数
        CuckooParam mParams;

        // Mod计算实例，size() = 哈希函数数量
        std::vector<Mod> mMods;
        // 存储输入元素的 hash 值，若使用 CuckooIndex 提供的，则使用 AES 来计算哈希值
        std::vector<block> mVals;
        // N * hNum，存储所有元素的位置
        Matrix<u32> mLocations;
        // 存储 bins的 vector
        std::vector<Bin> mBins;
        // 存数 stash 的 vector
        std::vector<Bin> mStash;

        // The total number of (re)inserts that were required,
        // 所需(重新)插入的总数
        u64 mTotalTries;

        // 遍历主哈希表 mBins，对每个桶进行检查
        // 对于每个非空 Bin，打印出桶的索引号、关联的输入索引和哈希索引
        // 遍历备用哈希表 mStash，对每个非空桶进行相同的操作
        // 打印结束
        void print() const;

        // 根据集合大小n、安全参数statSecParam、stash的size和哈希函数的数量h构造CuckooParam
        static CuckooParam selectParams(const u64 &n, const u64 &statSecParam, const u64 &stashSize, const u64 &h);

        // 初始化函数，调用 selectParams 方法生成 CuckooParam 进而初始化
        void init(const u64 &n, const u64 &statSecParam, u64 stashSize, u64 h);

        // 初始化函数，根据 CuckooParam 初始化
        void init(const CuckooParam &params);

        // insert unhashed items into the table using the provided hashing seed.
        // set startIdx to be the first idx of the items being inserted. When
        // find is called, it will return these indexes.
        // 通过给定的哈希种子将未经哈希的项插入到索引中
        // 可以设置 startIdx 作为要插入的项的第一个索引
        // 当调用 find 函数时，它将返回这些索引
        // 内置 AES 进行哈希
        void insert(span<block> items, block hashingSeed, u64 startIdx = 0);

        // insert pre hashed items into the table.
        // set startIdx to be the first idx of the items being inserted. When
        // find is called, it will return these indexes.
        // 将预先哈希的项插入到索引中，调用 probeInsert 函数执行实际的插入操作
        // 可以设置 startIdx 作为要插入的项的第一个索引
        // 当调用 find 函数时，它将返回这些索引
        void insert(span<const block> items, u64 startIdx = 0);

        // insert single index with pre hashed values with error checking
        // 使用预先哈希的值插入单个索引，并进行错误检查
        void insert(const u64 &IdxItem, const block &hashes);

        // insert several items with pre-hashed values with error checking
        // void insert(span<u64> itemIdxs, span<block> hashs);

        // insert several items with pre-hashed values
        // 使用预先哈希的值插入多个项，实际的插入操作
        void probeInsert(span<u64> itemIdxs);

        // 单独插入某个item, 输入为itemIdx hashIdx tryIdx
        void insertOne(u64 itemIdx, u64 hashIdx, u64 tryIdx);

        // 该函数用于计算给定哈希值对应的哈希表中的行索引
        // 调用 buildRow32 和 buildRow 函数来计算哈希值的行索引，并将结果写入到提供的矩阵视图
        void computeLocations(span<const block> hashes, oc::MatrixView<u32> rows);

        // FindResult 用于存储查找结果
        // mInputIdx：表示找到的输入项的索引
        // mCuckooPosition：表示在Cuckoo哈希表中的位置
        struct FindResult
        {
            u64 mInputIdx;
            u64 mCuckooPositon;

            operator bool() const
            {
                return mInputIdx != ~0ull;
            }
        };

        // find a single item with pre-hashed values and error checking.
        // 通过预先哈希的值查找单个项，并进行错误检查
        FindResult find(const block &hash);

        // find several items with pre hashed values, the indexes that are found are written to the idxs array.
        // 通过预先哈希的值查找多个项，并将找到的项的索引写入到提供的 idxs 数组中
        void find(span<block> hashes, span<u64> idxs);

        // find several items with pre hashed values, the indexes that are found are written to the idxs array.
        // void find(const u64& numItems, const  block* hashes, const u64* idxs);

        // checks that the cuckoo index is correct
        // 验证Cuckoo索引的正确性。它会对输入项进行哈希，并检查哈希值是否与存储在Cuckoo哈希表中的值匹配
        // 如果验证失败，则会引发异常
        void validate(span<block> inputs, block hashingSeed);

        // Return the number of items in the stash.
        // 计算溢出区 stash 的真实数量
        u64 stashUtilization() const;

        // == 运算符重载
        bool operator==(const CuckooIndex &cmp) const;
        // != 运算符重载
        bool operator!=(const CuckooIndex &cmp) const;

        // 根据输入索引和哈希索引获取哈希表 mLocations 中的哈希值，用于后续的查找和插入操作
        u64 getHash(const u64 &inputIdx, const u64 &hashIdx);

        static u8 minCollidingHashIdx(u64 target, block &hashes, u8 numHashFunctions, u64 numBins) { return -1; }
    };

    // 将 CuckooStash 输出到控制台
    // 非类型模板参数的模板声明, 允许在编译时提供一个值作为模板参数
    template <CuckooTypes Mode = ThreadSafe>
    inline std::ostream &operator<<(std::ostream &o, const CuckooIndex<Mode> &c)
    {
        o << "cuckoo:\n";
        for (u64 i = 0; i < c.mBins.size(); ++i)
        {
            o << i << "[";
            if (c.mBins[i].isEmpty())
            {
                o << "_]\n";
            }
            else
            {
                auto idx = c.mBins[i].idx();
                o << idx << " " << c.mBins[i].hashIdx();

                o << "],  { ";

                for (u64 j = 0; j < c.mParams.mNumHashes; ++j)
                {
                    if (j)
                        o << ", ";
                    o << c.mLocations(idx, j);
                }
                o << "}\n";
            }
        }
        for (u64 i = 0; i < c.mStash.size(); ++i)
        {

            o << "S" << i << "[";
            if (c.mBins[i].isEmpty())
            {
                o << "_";
            }
            else
            {
                o << c.mBins[i].idx() << " " << c.mBins[i].hashIdx();
            }

            o << "]\n";
        }

        o << std::endl;
        return o;
    }
}
