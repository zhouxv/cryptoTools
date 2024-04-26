#include <cryptoTools/Common/CuckooIndex.h>
#include <cryptoTools/Crypto/RandomOracle.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Common/Log.h>
#include <numeric>
#include <random>
#include <algorithm>
#include <mutex>

#define CUCKOO_BATCH_SIZE 8

namespace osuCrypto
{

    // parameters for k=2 hash functions, 2^n items, and statistical security 40
    // 2-way CuckooHash 的参数设置，按照顺序为 stashSize、scaler、mNumHashes、mN
    CuckooParam k2n32s40CuckooParam{4, 2.4, 2, u64(1) << 32};
    CuckooParam k2n30s40CuckooParam{4, 2.4, 2, u64(1) << 30};
    CuckooParam k2n28s40CuckooParam{2, 2.4, 2, u64(1) << 28};
    CuckooParam k2n24s40CuckooParam{2, 2.4, 2, u64(1) << 24};
    CuckooParam k2n20s40CuckooParam{2, 2.4, 2, u64(1) << 20};
    CuckooParam k2n16s40CuckooParam{3, 2.4, 2, u64(1) << 16};
    CuckooParam k2n12s40CuckooParam{5, 2.4, 2, u64(1) << 12};
    CuckooParam k2n08s40CuckooParam{8, 2.4, 2, u64(1) << 8};

    // not sure if this needs a stash of 40, but should be safe enough.
    CuckooParam k2n07s40CuckooParam{40, 2.4, 2, 1 << 7};
    CuckooParam k2n06s40CuckooParam{40, 2.4, 2, 1 << 6};
    CuckooParam k2n05s40CuckooParam{40, 2.4, 2, 1 << 5};
    CuckooParam k2n04s40CuckooParam{40, 2.4, 2, 1 << 4};
    CuckooParam k2n03s40CuckooParam{40, 2.4, 2, 1 << 3};
    CuckooParam k2n02s40CuckooParam{40, 2.4, 2, 1 << 2};
    CuckooParam k2n01s40CuckooParam{40, 2.4, 2, 1 << 1};

#ifndef ENABLE_SSE

    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_cmpgt_epi64&ig_expand=1038
    inline block _mm_cmpgt_epi64(const block &a, const block &b)
    {
        std::array<u64, 2> ret;
        ret[0] = a.get<u64>()[0] > b.get<u64>()[0] ? -1ull : 0ull;
        ret[1] = a.get<u64>()[1] > b.get<u64>()[1] ? -1ull : 0ull;

        // auto t = ::_mm_cmpgt_epi64(*(__m128i*) & a, *(__m128i*) & b);;
        // block ret2 = *(block*)&t;
        // assert(ret2 == ret);

        return ret;
    }

    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_cmpeq_epi64&ig_expand=1038,900
    inline block _mm_cmpeq_epi64(const block &a, const block &b)
    {
        std::array<u64, 2> ret;
        ret[0] = a.get<u64>()[0] == b.get<u64>()[0] ? -1ull : 0ull;
        ret[1] = a.get<u64>()[1] == b.get<u64>()[1] ? -1ull : 0ull;

        // auto t = ::_mm_cmpeq_epi64(*(__m128i*) & a, *(__m128i*) & b);;
        // block ret2 = *(block*)&t;
        // assert(ret2 == ret);

        return ret;
    }

    // https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_mm_sub_epi64&ig_expand=1038,900,6922
    inline block _mm_sub_epi64(const block &a, const block &b)
    {
        std::array<u64, 2> ret;
        ret[0] = a.get<u64>(0) - b.get<u64>(0);
        ret[1] = a.get<u64>(1) - b.get<u64>(1);

        // auto t = ::_mm_sub_epi64(*(__m128i*) & a, *(__m128i*) & b);;
        // block ret2 = *(block*)&t;
        // assert(ret2 == ret);

        return ret;
    }

#endif

    void buildRow(const block &hash, u32 *row, span<Mod> mods)
    {
        using IdxType = u32;
        // auto h = hash;
        // std::set<u64> ss;
        // u64 i = 0;
        // while (ss.size() != mWeight)
        //{
        //	auto hh = oc::AES(h).ecbEncBlock(block(0,i++));
        //	ss.insert(hh.as<u64>()[0] % mSparseSize);
        // }
        // std::copy(ss.begin(), ss.end(), row);
        // return;
        u64 mWeight = mods.size();
        if (mWeight == 3)
        {
            u32 *rr = (u32 *)&hash;
            auto rr0 = *(u64 *)(&rr[0]);
            auto rr1 = *(u64 *)(&rr[1]);
            auto rr2 = *(u64 *)(&rr[2]);
            row[0] = (IdxType)mods[0].mod(rr0);
            row[1] = (IdxType)mods[1].mod(rr1);
            row[2] = (IdxType)mods[2].mod(rr2);

            assert(row[0] < mods[0].mVal);
            assert(row[1] < mods[0].mVal);
            assert(row[2] < mods[0].mVal);

            auto min = std::min<IdxType>(row[0], row[1]);
            auto max = row[0] + row[1] - min;

            if (max == row[1])
            {
                ++row[1];
                ++max;
            }

            if (row[2] >= min)
                ++row[2];

            if (row[2] >= max)
                ++row[2];
        }
        else
        {
            auto hh = hash;
            for (u64 j = 0; j < mWeight; ++j)
            {
                auto modulus = mods[j].mVal;

                hh = hh.gf128Mul(hh);
                // std::memcpy(&h, (u8*)&hash + byteIdx, mIdxSize);
                auto colIdx = hh.get<u64>(0) % modulus;

                auto iter = row;
                auto end = row + j;
                while (iter != end)
                {
                    if (*iter <= colIdx)
                        ++colIdx;
                    else
                        break;
                    ++iter;
                }

                while (iter != end)
                {
                    end[0] = end[-1];
                    --end;
                }

                *iter = static_cast<IdxType>(colIdx);
            }
        }
    }

    // hash是元素的哈希值, row是存储location的结构,div是模数
    void buildRow32(const block *hash, u32 *row, span<Mod> divs)
    {
        using IdxType = u32;

        // hashNum == 3
        if (divs.size() == 3 /* && mSparseSize < std::numeric_limits<u32>::max()*/)
        {
            const auto weight = 3;

            // 3 表示哈希数量, 16 表示每次处理 16 个哈希值
            // 存储 3-way hash, 每个存储 16 个 block, 即 32 个 u64 数据
            block row128_[3][16];

            // 实际上相当于计算 h1 h2 h3的输出
            for (u64 i = 0; i < weight; ++i)
            {
                // 16 个 block 转 32个 u64
                auto ll = (u64 *)row128_[i];

                for (u64 j = 0; j < 32; ++j)
                {
                    // 从 0 32 64 bits 开始, 取三个 u64 出来
                    memcpy(&ll[j], hash[j].data() + sizeof(u32) * i, sizeof(u64));
                }
                // 取模
                divs[i].mod32(ll);
            }

            // 根据哈希表项的不同情况进行调整，以解决哈希冲突并确保哈希表的正确性和性能
            // 前16个和后16个元素的三个哈希值
            for (u64 i = 0; i < 2; ++i)
            {
                std::array<block, 8> mask, max, min;
                // auto& row128 = *(std::array<std::array<block, 16>, 3>*)(((block*)row128_) + 8 * i);

                std::array<block *, 3> row128{
                    row128_[0] + i * 8,
                    row128_[1] + i * 8,
                    row128_[2] + i * 8};

                // if (i)
                //{
                //	memcpy(row128[0], &row128[0][i * 8], sizeof(block) * 8);
                //	memcpy(row128[1], &row128[1][i * 8], sizeof(block) * 8);
                //	memcpy(row128[2], &row128[2][i * 8], sizeof(block) * 8);
                // }

                // mask = a > b ? -1 : 0;
                // 如果 a>b, 则 mask 填充全 1 序列, 否则为 0
                mask[0] = _mm_cmpgt_epi64(row128[0][0], row128[1][0]);
                mask[1] = _mm_cmpgt_epi64(row128[0][1], row128[1][1]);
                mask[2] = _mm_cmpgt_epi64(row128[0][2], row128[1][2]);
                mask[3] = _mm_cmpgt_epi64(row128[0][3], row128[1][3]);
                mask[4] = _mm_cmpgt_epi64(row128[0][4], row128[1][4]);
                mask[5] = _mm_cmpgt_epi64(row128[0][5], row128[1][5]);
                mask[6] = _mm_cmpgt_epi64(row128[0][6], row128[1][6]);
                mask[7] = _mm_cmpgt_epi64(row128[0][7], row128[1][7]);

                // 元素的异或，得到两者之间的差异
                min[0] = row128[0][0] ^ row128[1][0];
                min[1] = row128[0][1] ^ row128[1][1];
                min[2] = row128[0][2] ^ row128[1][2];
                min[3] = row128[0][3] ^ row128[1][3];
                min[4] = row128[0][4] ^ row128[1][4];
                min[5] = row128[0][5] ^ row128[1][5];
                min[6] = row128[0][6] ^ row128[1][6];
                min[7] = row128[0][7] ^ row128[1][7];

                // max = max(a,b)
                // 得到 a,b 中较大的值
                max[0] = (min[0]) & mask[0];
                max[1] = (min[1]) & mask[1];
                max[2] = (min[2]) & mask[2];
                max[3] = (min[3]) & mask[3];
                max[4] = (min[4]) & mask[4];
                max[5] = (min[5]) & mask[5];
                max[6] = (min[6]) & mask[6];
                max[7] = (min[7]) & mask[7];
                max[0] = max[0] ^ row128[1][0];
                max[1] = max[1] ^ row128[1][1];
                max[2] = max[2] ^ row128[1][2];
                max[3] = max[3] ^ row128[1][3];
                max[4] = max[4] ^ row128[1][4];
                max[5] = max[5] ^ row128[1][5];
                max[6] = max[6] ^ row128[1][6];
                max[7] = max[7] ^ row128[1][7];

                // min = min(a,b)
                // 得到 a,b 中较小的值
                min[0] = min[0] ^ max[0];
                min[1] = min[1] ^ max[1];
                min[2] = min[2] ^ max[2];
                min[3] = min[3] ^ max[3];
                min[4] = min[4] ^ max[4];
                min[5] = min[5] ^ max[5];
                min[6] = min[6] ^ max[6];
                min[7] = min[7] ^ max[7];

                // if (max == b)
                //   ++b
                //   ++max
                // 判断是否相等
                mask[0] = _mm_cmpeq_epi64(max[0], row128[1][0]);
                mask[1] = _mm_cmpeq_epi64(max[1], row128[1][1]);
                mask[2] = _mm_cmpeq_epi64(max[2], row128[1][2]);
                mask[3] = _mm_cmpeq_epi64(max[3], row128[1][3]);
                mask[4] = _mm_cmpeq_epi64(max[4], row128[1][4]);
                mask[5] = _mm_cmpeq_epi64(max[5], row128[1][5]);
                mask[6] = _mm_cmpeq_epi64(max[6], row128[1][6]);
                mask[7] = _mm_cmpeq_epi64(max[7], row128[1][7]);
                // row128[1][0] - mask
                // max == b, row128[1][0] - 1111
                // max != b, row128[1][0] - 0000
                row128[1][0] = _mm_sub_epi64(row128[1][0], mask[0]);
                row128[1][1] = _mm_sub_epi64(row128[1][1], mask[1]);
                row128[1][2] = _mm_sub_epi64(row128[1][2], mask[2]);
                row128[1][3] = _mm_sub_epi64(row128[1][3], mask[3]);
                row128[1][4] = _mm_sub_epi64(row128[1][4], mask[4]);
                row128[1][5] = _mm_sub_epi64(row128[1][5], mask[5]);
                row128[1][6] = _mm_sub_epi64(row128[1][6], mask[6]);
                row128[1][7] = _mm_sub_epi64(row128[1][7], mask[7]);

                max[0] = _mm_sub_epi64(max[0], mask[0]);
                max[1] = _mm_sub_epi64(max[1], mask[1]);
                max[2] = _mm_sub_epi64(max[2], mask[2]);
                max[3] = _mm_sub_epi64(max[3], mask[3]);
                max[4] = _mm_sub_epi64(max[4], mask[4]);
                max[5] = _mm_sub_epi64(max[5], mask[5]);
                max[6] = _mm_sub_epi64(max[6], mask[6]);
                max[7] = _mm_sub_epi64(max[7], mask[7]);

                // if (c >= min)
                //   ++c
                mask[0] = _mm_cmpgt_epi64(min[0], row128[2][0]);
                mask[1] = _mm_cmpgt_epi64(min[1], row128[2][1]);
                mask[2] = _mm_cmpgt_epi64(min[2], row128[2][2]);
                mask[3] = _mm_cmpgt_epi64(min[3], row128[2][3]);
                mask[4] = _mm_cmpgt_epi64(min[4], row128[2][4]);
                mask[5] = _mm_cmpgt_epi64(min[5], row128[2][5]);
                mask[6] = _mm_cmpgt_epi64(min[6], row128[2][6]);
                mask[7] = _mm_cmpgt_epi64(min[7], row128[2][7]);
                mask[0] = mask[0] ^ oc::AllOneBlock;
                mask[1] = mask[1] ^ oc::AllOneBlock;
                mask[2] = mask[2] ^ oc::AllOneBlock;
                mask[3] = mask[3] ^ oc::AllOneBlock;
                mask[4] = mask[4] ^ oc::AllOneBlock;
                mask[5] = mask[5] ^ oc::AllOneBlock;
                mask[6] = mask[6] ^ oc::AllOneBlock;
                mask[7] = mask[7] ^ oc::AllOneBlock;
                row128[2][0] = _mm_sub_epi64(row128[2][0], mask[0]);
                row128[2][1] = _mm_sub_epi64(row128[2][1], mask[1]);
                row128[2][2] = _mm_sub_epi64(row128[2][2], mask[2]);
                row128[2][3] = _mm_sub_epi64(row128[2][3], mask[3]);
                row128[2][4] = _mm_sub_epi64(row128[2][4], mask[4]);
                row128[2][5] = _mm_sub_epi64(row128[2][5], mask[5]);
                row128[2][6] = _mm_sub_epi64(row128[2][6], mask[6]);
                row128[2][7] = _mm_sub_epi64(row128[2][7], mask[7]);

                // if (c >= max)
                //   ++c
                mask[0] = _mm_cmpgt_epi64(max[0], row128[2][0]);
                mask[1] = _mm_cmpgt_epi64(max[1], row128[2][1]);
                mask[2] = _mm_cmpgt_epi64(max[2], row128[2][2]);
                mask[3] = _mm_cmpgt_epi64(max[3], row128[2][3]);
                mask[4] = _mm_cmpgt_epi64(max[4], row128[2][4]);
                mask[5] = _mm_cmpgt_epi64(max[5], row128[2][5]);
                mask[6] = _mm_cmpgt_epi64(max[6], row128[2][6]);
                mask[7] = _mm_cmpgt_epi64(max[7], row128[2][7]);
                mask[0] = mask[0] ^ oc::AllOneBlock;
                mask[1] = mask[1] ^ oc::AllOneBlock;
                mask[2] = mask[2] ^ oc::AllOneBlock;
                mask[3] = mask[3] ^ oc::AllOneBlock;
                mask[4] = mask[4] ^ oc::AllOneBlock;
                mask[5] = mask[5] ^ oc::AllOneBlock;
                mask[6] = mask[6] ^ oc::AllOneBlock;
                mask[7] = mask[7] ^ oc::AllOneBlock;
                row128[2][0] = _mm_sub_epi64(row128[2][0], mask[0]);
                row128[2][1] = _mm_sub_epi64(row128[2][1], mask[1]);
                row128[2][2] = _mm_sub_epi64(row128[2][2], mask[2]);
                row128[2][3] = _mm_sub_epi64(row128[2][3], mask[3]);
                row128[2][4] = _mm_sub_epi64(row128[2][4], mask[4]);
                row128[2][5] = _mm_sub_epi64(row128[2][5], mask[5]);
                row128[2][6] = _mm_sub_epi64(row128[2][6], mask[6]);
                row128[2][7] = _mm_sub_epi64(row128[2][7], mask[7]);

                // if (sizeof(IdxType) == 2)
                //{
                //	std::array<__m256i*, 3> row256{
                //		(__m256i*)row128[0],
                //		(__m256i*)row128[1],
                //		(__m256i*)row128[2]
                //	};

                //	//
                // r[0][0],r[1][1],
                // r[2][2],r[1][0],
                // r[1][1],r[1][2],
                //
                //}
                // else
                {
                    u64 mWeight = divs.size();
                    for (u64 j = 0; j < mWeight; ++j)
                    {
                        IdxType *__restrict rowi = row + mWeight * 16 * i;
                        u64 *__restrict row64 = (u64 *)(row128[j]);

                        // 将
                        rowi[mWeight * 0 + j] = row64[0];
                        rowi[mWeight * 1 + j] = row64[1];
                        rowi[mWeight * 2 + j] = row64[2];
                        rowi[mWeight * 3 + j] = row64[3];
                        rowi[mWeight * 4 + j] = row64[4];
                        rowi[mWeight * 5 + j] = row64[5];
                        rowi[mWeight * 6 + j] = row64[6];
                        rowi[mWeight * 7 + j] = row64[7];

                        rowi += 8 * mWeight;
                        row64 += 8;

                        rowi[mWeight * 0 + j] = row64[0];
                        rowi[mWeight * 1 + j] = row64[1];
                        rowi[mWeight * 2 + j] = row64[2];
                        rowi[mWeight * 3 + j] = row64[3];
                        rowi[mWeight * 4 + j] = row64[4];
                        rowi[mWeight * 5 + j] = row64[5];
                        rowi[mWeight * 6 + j] = row64[6];
                        rowi[mWeight * 7 + j] = row64[7];
                    }
                }
                // for (u64 k = 0; k < 16; ++k)
                //{
                //	IdxType row2[3];
                //	buildRow(hash[k + i * 16], row2);
                //	auto rowi = row + mWeight * 16 * i;
                //	//assert(rowi == row + mWeight * k);
                //	assert(row2[0] == rowi[mWeight * k + 0]);
                //	assert(row2[1] == rowi[mWeight * k + 1]);
                //	assert(row2[2] == rowi[mWeight * k + 2]);
                // }
            }
        }
        else
        {
            u64 mWeight = divs.size();
            for (u64 k = 0; k < 32; ++k)
            {
                buildRow(hash[k], row, divs);
                row += mWeight;
            }
        }
    }

    template <CuckooTypes Mode>
    CuckooIndex<Mode>::CuckooIndex()
        : mTotalTries(0)
    {
    }

    template <CuckooTypes Mode>
    CuckooIndex<Mode>::~CuckooIndex()
    {
    }

    template <CuckooTypes Mode>
    bool CuckooIndex<Mode>::operator==(const CuckooIndex &cmp) const
    {
        if (mBins.size() != cmp.mBins.size())
            throw std::runtime_error("");

        if (mStash.size() != cmp.mStash.size())
            throw std::runtime_error("");

        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].load() != cmp.mBins[i].load())
            {
                return false;
            }
        }

        for (u64 i = 0; i < mStash.size(); ++i)
        {
            if (mStash[i].load() != cmp.mStash[i].load())
            {
                return false;
            }
        }

        return true;
    }

    template <CuckooTypes Mode>
    bool CuckooIndex<Mode>::operator!=(const CuckooIndex &cmp) const
    {
        return !(*this == cmp);
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::print() const
    {

        std::cout << "Cuckoo Hasher  " << std::endl;

        // 遍历主哈希表 mBins，对每个桶进行检查
        // 对于每个非空 Bin，打印出桶的索引号、关联的输入索引和哈希索引
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            std::cout << "Bin #" << i;

            if (mBins[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mBins[i].idx() << "  hIdx=" << mBins[i].hashIdx() << std::endl;
            }
        }

        // 遍历备用哈希表 mStash，对每个非空桶进行相同的操作。
        for (u64 i = 0; i < mStash.size() && mStash[i].isEmpty() == false; ++i)
        {
            std::cout << "Bin #" << i;

            if (mStash[i].isEmpty())
            {
                std::cout << " - " << std::endl;
            }
            else
            {
                std::cout << "    c_idx=" << mStash[i].idx() << "  hIdx=" << mStash[i].hashIdx() << std::endl;
            }
        }
        std::cout << std::endl;
    }

    template <CuckooTypes Mode>
    CuckooParam CuckooIndex<Mode>::selectParams(const u64 &n, const u64 &statSecParam, const u64 &stashSize, const u64 &hh)
    {
        double nn = std::log2(n);

        auto h = hh ? hh : 3;

        if (stashSize == 0 && h == 3)
        {
            auto nnf = log2floor(n);
            if (nnf < 9)
            {
                struct Line
                {
                    double slope, y;
                };
                std::array<Line, 10> lines{{
                    Line{5.5, 6.35},   // 0
                    Line{5.5, 6.35},   // 1
                    Line{5.5, 6.35},   // 2
                    Line{8.5, -0.07},  // 3
                    Line{13.4, -6.74}, // 4
                    Line{21.9, -16.1}, // 5
                    Line{57.8, -62.6}, // 6
                    Line{100, -113},   // 7
                    Line{142, -158},   // 8
                }};

                // secParam = slope * e + y
                // e = (secParam - y ) / slope;
                auto e = (statSecParam - lines[nnf].y) / lines[nnf].slope;

                return CuckooParam{0, e, 3, n};
            }
            else
            {

                // parameters that have been experimentally determined.
                double a = 240;
                double b = -std::log2(n) - 256;

                auto e = (statSecParam - b) / a;

                // we have the statSecParam = a e + b, where e = |cuckoo|/|set| is the expenation factor
                // therefore we have that
                //
                //   e = (statSecParam - b) / a
                //
                return CuckooParam{0, e, 3, n};
            }
        }
        else if (h == 2)
        {
            // parameters that have been experimentally determined.
            double
                a = -0.8,
                b = 3.3,
                c = 2.5,
                d = 14,
                f = 5,
                g = 0.65;

            // for e > 8,   statSecParam = (1 + 0.65 * stashSize) (b * std::log2(e) + a + nn).
            // for e < 8,   statSecParam -> 0 at e = 2. This is what the pow(...) does...
            auto sec = [&](double e)
            { return (1 + g * stashSize) * (b * std::log2(e) + a + nn - (f * nn + d) * std::pow(e, -c)); };

            // increase e util we have large enough security.
            double e = 1;
            double s = 0;
            while (s < statSecParam)
            {
                e += 1;
                s = sec(e);
            }

            return CuckooParam{0, e, 2, n};
        }

        throw std::runtime_error(LOCATION);
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::init(const u64 &n, const u64 &statSecParam, u64 stashSize, u64 h)
    {
        init(selectParams(n, statSecParam, stashSize, h));
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::init(const CuckooParam &params)
    {
        mParams = params;

        if (CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT < params.mNumHashes)
            throw std::runtime_error("parameters exceeded the maximum number of hash functions are are supported. see getHash(...); " LOCATION);

        // 根据集合大小 resize mVals 的内存空间，并初始化为 AllOneBlock
        mVals.resize(mParams.mN, AllOneBlock);

        // 将 mLocations 矩阵的大小调整为 mParams.mN 行、params.mNumHashes 列，并将所有元素初始化为未初始化状态
        mLocations.resize(mParams.mN, params.mNumHashes, AllocType::Uninitialized);

        u64 binCount = mParams.numBins();

        // 根据 binCount，初始化 mBins、mStash、numBins 和 binMask
        mBins.resize(binCount);
        mStash.resize(mParams.mStashSize);
        mNumBins = binCount;
        mNumBinMask = mParams.binMask();

        // 根据 mNumHashes，初始化 mMods
        mMods.resize(mParams.mNumHashes);
        for (u64 i = 0; i < mMods.size(); ++i)
        {
            mMods[i] = Mod(binCount - i);
        }
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(span<const block> items, u64 startIdx)
    {
        std::array<u64, 32> idxs;
        // 检查插入的范围是否超出了哈希表的大小，如果超出则抛出异常
        if (items.size() + startIdx > mVals.size())
            throw RTE_LOC;

        // 检查起始索引位置是否已经被插入过，如果已经插入过则抛出异常
        if (neq(mVals[startIdx], AllOneBlock))
        {
            std::cout << IoStream::lock << "cuckoo index " << startIdx << " already inserted" << std::endl
                      << IoStream::unlock;
            throw std::runtime_error(LOCATION);
        }

        // 将 items 中的数据拷贝到哈希表的指定位置 startIdx 处
        memcpy(&mVals[startIdx], items.data(), items.size() * sizeof(block));

        // 将插入的索引分成大小为 32 的块，并逐个处理
        // 对于每个块
        for (u64 i = 0; i < u64(items.size()); i += u64(idxs.size()))
        {
            // 计算当前块剩余的item的数量
            auto min = std::min<u64>(items.size() - i, idxs.size());

            // 记录每个item对应的idx
            for (u64 j = 0, jj = i; j < min; ++j, ++jj)
            {
                idxs[j] = jj + startIdx;
            }

            // 计算当前块的元素对应的location，写入mLocations中
            computeLocations(items.subspan(i, min), oc::MatrixView<u32>(mLocations.data(i + startIdx), min, mParams.mNumHashes));

            probeInsert(span<u64>(idxs.data(), min));
        }
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(span<block> items, block hashingSeed, u64 startIdx)
    {
        // std::array<block, 32> hashs;
        // std::array<u64, 32> idxs;
        AES hasher(hashingSeed);
        AlignedUnVector<block> h(items.size());

        // 对 items 里的所有 block 进行hash
        hasher.hashBlocks(items, h);

        insert(h, startIdx);
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::computeLocations(span<const block> hashes, oc::MatrixView<u32> rows)
    {
        u64 ii = 32;
        u64 i = 0;
        while (ii < hashes.size())
        {
            buildRow32(hashes.data() + i, rows.data(i), mMods);
            i += 32;
            ii += 32;
        }

        while (i < hashes.size())
        {
            buildRow(hashes[i], rows.data(i), mMods);
            ++i;
        }
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::insert(const u64 &inputIdx, const block &hashs)
    {
        insert(span<const block>{&hashs, 1}, inputIdx);
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::probeInsert(
        span<u64> inputIdxsMaster)
    {
        const u64 nullIdx = (u64(-1) >> 8);

        // curHashIdxs 是当前使用的哈希函数的索引
        // curAddrs 存储了当前哈希函数计算出的地址
        // inputIdxs 存储了待插入的索引
        // tryCounts 存储了尝试插入的次数。
        std::array<u64, CUCKOO_BATCH_SIZE> curHashIdxs, curAddrs, inputIdxs, tryCounts;

        // 初始化一下相关参数
        u64 i = 0;
        for (; i < CUCKOO_BATCH_SIZE; ++i)
        {
            if (i < inputIdxsMaster.size())
            {

                inputIdxs[i] = inputIdxsMaster[i];
                curHashIdxs[i] = 0;
                tryCounts[i] = 0;
            }
            else
            {
                inputIdxs[i] = nullIdx;
            }
        }

#if CUCKOO_BATCH_SIZE == 8
        // 如果输入索引数组的大小超过了 CUCKOO_BATCH_SIZE，并且哈希函数的数量为3，那么使用批量处理
        if (inputIdxsMaster.size() > 8 && mParams.mNumHashes == 3)
        {
            // 8 16 24, 当 i 指向 24 时, 循环结束
            while (i < inputIdxsMaster.size() - 8)
            {

                // this data fetch can be slow (after the first loop).
                // As such, lets do several fetches in parallel.
                // 首先获取每个输入索引对应的哈希地址
                curAddrs[0] = getHash(inputIdxs[0], curHashIdxs[0]);
                curAddrs[1] = getHash(inputIdxs[1], curHashIdxs[1]);
                curAddrs[2] = getHash(inputIdxs[2], curHashIdxs[2]);
                curAddrs[3] = getHash(inputIdxs[3], curHashIdxs[3]);
                curAddrs[4] = getHash(inputIdxs[4], curHashIdxs[4]);
                curAddrs[5] = getHash(inputIdxs[5], curHashIdxs[5]);
                curAddrs[6] = getHash(inputIdxs[6], curHashIdxs[6]);
                curAddrs[7] = getHash(inputIdxs[7], curHashIdxs[7]);

                // same thing here, this fetch is slow. Do them in parallel.
                // u64 newVal0 = inputIdxs[0] | (curHashIdxs[0] << 56);
                // oldVals[i] =
                // 尝试将索引插入到对应的地址上
                // idx 为输入索引, curHashIdxs为使用的hash函数
                mBins[curAddrs[0]].swap(inputIdxs[0], curHashIdxs[0]);
                mBins[curAddrs[1]].swap(inputIdxs[1], curHashIdxs[1]);
                mBins[curAddrs[2]].swap(inputIdxs[2], curHashIdxs[2]);
                mBins[curAddrs[3]].swap(inputIdxs[3], curHashIdxs[3]);
                mBins[curAddrs[4]].swap(inputIdxs[4], curHashIdxs[4]);
                mBins[curAddrs[5]].swap(inputIdxs[5], curHashIdxs[5]);
                mBins[curAddrs[6]].swap(inputIdxs[6], curHashIdxs[6]);
                mBins[curAddrs[7]].swap(inputIdxs[7], curHashIdxs[7]);

                for (u64 j = 0; j < 8; ++j)
                {

                    if (inputIdxs[j] == nullIdx)
                    {
                        // 如果第 j 个位置的插入空的bin里, 取 i 对应的新元素
                        inputIdxs[j] = inputIdxsMaster[i];
                        // buildRow(hashs[i], mLocations.data(inputIdxs[j]), mMods);
                        // mVals[inputIdxs[j]] = hashs[i];
                        // mLocations[inputIdxs[j]] = expand(hashs[i], 3,mNumBins, mNumBinMask);
                        curHashIdxs[j] = 0;
                        tryCounts[j] = 0;

                        // 将i指向新的插入值
                        ++i;
                    }
                    else
                    {
                        // 如果第 j 个位置的插入存在元素的bin里, 还能继续重排, 则取新的curHashIdxs, 插入次数+1
                        // 否则插入到stash中
                        if (tryCounts[j] != mReinsertLimit)
                        {
                            curHashIdxs[j] = (1 + curHashIdxs[j]) % 3;
                            ++tryCounts[j];
                        }
                        else
                        {
                            // int里是-1, 但是在u64里,就是2^64-1
                            u64 k = ~u64(0);

                            // k 迭代至 空的stash bin
                            do
                            {
                                // 从0开始
                                ++k;
                                if (k == mStash.size())
                                {
                                    std::cout << "cuckoo stash overflow" << std::endl;
                                    throw RTE_LOC;
                                }
                            } while (mStash[k].isEmpty() == false);

                            mStash[k].swap(inputIdxs[j], curHashIdxs[j]);

                            // 读取新的索引
                            inputIdxs[j] = inputIdxsMaster[i];
                            // mLocations[inputIdxs[j]] = expand(hashs[i], 3, mNumBins, mNumBinMask);
                            // buildRow(hashs[i], mLocations.data(inputIdxs[j]), mMods);
                            // mVals[inputIdxs[j]] = hashs[i];
                            curHashIdxs[j] = 0;
                            tryCounts[j] = 0;

                            // 将i指向新的索引
                            ++i;
                        }
                    }
                }
            }
        }
#endif

        // 把当前 CUCKOO_BATCH_SIZE 里面的 inputIdxs 插入 insertOne
        for (u64 j = 0; j < CUCKOO_BATCH_SIZE; ++j)
        {

            if (inputIdxs[j] != nullIdx)
            {
                insertOne(inputIdxs[j], curHashIdxs[j], tryCounts[j]);
            }
        }

        // 把剩下的 input 插入进去
        while (i < inputIdxsMaster.size())
        {
            // mLocations[inputIdxsMaster[i]] = expand(hashs[i], mMods, mNumBinMask);
            // buildRow(hashs[i], mLocations.data(inputIdxsMaster[i]), mMods);
            // mVals[inputIdxsMaster[i]] = hashs[i];
            insertOne(inputIdxsMaster[i], 0, 0);
            ++i;
        }
    }

    // 和 ProbeInsert 里的实现是类似的
    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::insertOne(
        u64 inputIdx, u64 curHashIdx, u64 tryIdx)
    {
        const u64 nullIdx = (u64(-1) >> 8);
        while (true)
        {
            auto curAddr = getHash(inputIdx, curHashIdx);
            mBins[curAddr].swap(inputIdx, curHashIdx);

            if (inputIdx == nullIdx)
            {
                return;
            }
            else
            {
                if (tryIdx != mReinsertLimit)
                {
                    curHashIdx = (1 + curHashIdx) % mParams.mNumHashes;
                    ++tryIdx;
                }
                else
                {
                    u64 k = ~u64(0);
                    do
                    {
                        ++k;
                        if (k == mStash.size())
                        {
                            std::cout << "cuckoo stash overflow" << std::endl;
                            std::cout << inputIdx << " { ";

                            for (u64 j = 0; j < mParams.mNumHashes; ++j)
                            {
                                if (j)
                                    std::cout << ", ";
                                std::cout << getHash(inputIdx, j);
                            }
                            std::cout << "}\n";
                            std::cout << *this << std::endl;
                            throw RTE_LOC;
                        }
                    } while (mStash[k].isEmpty() == false);
                    mStash[k].swap(inputIdx, curHashIdx);
                    return;
                }
            }
        }
    }

    template <CuckooTypes Mode>
    u64 CuckooIndex<Mode>::getHash(const u64 &inputIdx, const u64 &hashIdx)
    {
        assert(mVals[inputIdx] != AllOneBlock);
        assert(mLocations(inputIdx, hashIdx) < mBins.size());
        return mLocations(inputIdx, hashIdx);
        // return CuckooIndex<Mode>::getHash3(mLocations[inputIdx], hashIdx, mNumBinMask);
        // return CuckooIndex<Mode>::getHash(mLocations[inputIdx], hashIdx, mNumBins);
    }

    template <CuckooTypes Mode>
    typename CuckooIndex<Mode>::FindResult CuckooIndex<Mode>::find(
        const block &hashes_)
    {
        // auto hashes = expand(hashes_, mMods, mNumBinMask);
        auto hashes = hashes_;
        if (mParams.mNumHashes == 2)
        {
            std::array<u32, 2> addr;
            ;
            computeLocations(span<const block>(&hashes_, 1), MatrixView<u32>(addr.data(), 1, 2));

            std::array<u64, 2> val{
                mBins[addr[0]].load(),
                mBins[addr[1]].load()};

            if (val[0] != u64(-1))
            {
                u64 itemIdx = val[0] & (u64(-1) >> 8);

                bool match = eq(mVals[itemIdx], hashes);

                if (match)
                    return {itemIdx, addr[0]};
            }

            if (val[1] != u64(-1))
            {
                u64 itemIdx = val[1] & (u64(-1) >> 8);

                bool match = eq(mVals[itemIdx], hashes);

                if (match)
                    return {itemIdx, addr[1]};
            }

            // stash
            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
                u64 val = mStash[i].load();
                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mVals[itemIdx], hashes);

                    if (match)
                    {
                        return {itemIdx, i + mBins.size()};
                    }
                }

                ++i;
            }
        }
        else
        {
            std::array<u32, CUCKOOINDEX_MAX_HASH_FUNCTION_COUNT> addr;
            ;
            computeLocations(span<const block>(&hashes, 1), MatrixView<u32>(addr.data(), 1, mParams.mNumHashes));

            for (u64 i = 0; i < mParams.mNumHashes; ++i)
            {
                // u64 xrHashVal = getHash(hashes, i, mNumBins);
                // auto addr = (xrHashVal) % mBins.size();

                u64 val = mBins[addr[i]].load();

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mVals[itemIdx], hashes);

                    if (match)
                    {
                        return {itemIdx, addr[i]};
                    }
                }
            }

            u64 i = 0;
            while (i < mStash.size() && mStash[i].isEmpty() == false)
            {
                u64 val = mStash[i].load();

                if (val != u64(-1))
                {
                    u64 itemIdx = val & (u64(-1) >> 8);

                    bool match = eq(mVals[itemIdx], hashes);

                    if (match)
                    {
                        return {itemIdx, i + mBins.size()};
                    }
                }

                ++i;
            }
        }

        return {~0ull, ~0ull};
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::find(
        span<block> hashes,
        span<u64> idxs)
    {
#ifndef NDEBUG
        if (hashes.size() != idxs.size())
            throw std::runtime_error(LOCATION);
#endif

        for (u64 i = 0; i < hashes.size(); ++i)
        {
            // todo
            idxs[i] = find(hashes[i]).mCuckooPositon;
        }
    }

    template <CuckooTypes Mode>
    void CuckooIndex<Mode>::validate(span<block> inputs, block hashingSeed)
    {
        AES hasher(hashingSeed);
        u64 insertCount = 0;

        for (u64 i = 0; i < u64(inputs.size()); ++i)
        {

            block hash = hasher.hashBlock(inputs[i]);

            // hash = expand(hash, mMods, mNumBinMask);

            if (neq(hash, mVals[i]))
                throw std::runtime_error(LOCATION);

            if (neq(mVals[i], AllOneBlock))
            {
                ++insertCount;
                u64 matches(0);
                std::vector<u64> hashes(mParams.mNumHashes);
                for (u64 j = 0; j < mParams.mNumHashes; ++j)
                {
                    auto h = hashes[j] = getHash(i, j);
                    auto duplicate = (std::find(hashes.begin(), hashes.begin() + j, h) != (hashes.begin() + j));

                    if (duplicate == false && mBins[h].isEmpty() == false && mBins[h].idx() == i)
                    {
                        ++matches;
                    }
                }

                if (matches != 1)
                    throw std::runtime_error(LOCATION);
            }
        }

        u64 nonEmptyCount(0);
        for (u64 i = 0; i < mBins.size(); ++i)
        {
            if (mBins[i].isEmpty() == false)
                ++nonEmptyCount;
        }

        if (nonEmptyCount != insertCount)
            throw std::runtime_error(LOCATION);
    }

    template <CuckooTypes Mode>
    u64 CuckooIndex<Mode>::stashUtilization() const
    {
        u64 i = 0;
        while (i < mStash.size() && mStash[i].isEmpty() == false)
        {
            ++i;
        }

        return i;
    }

    // 模板类的显式实例化声明
    // 该语法告诉编译器在编译时生成 CuckooIndex<ThreadSafe> 类和 CuckooIndex<NotThreadSafe> 类的实例化代码
    // 这样做的目的是为了在编译期间确保模板类的实现被实例化，从而在链接时生成相应的目标代码
    template class CuckooIndex<ThreadSafe>;
    template class CuckooIndex<NotThreadSafe>;
}
