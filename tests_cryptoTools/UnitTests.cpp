#include <cryptoTools/Common/Log.h>
#include <functional>

#include "tests_cryptoTools/AES_Tests.h"
#include "tests_cryptoTools/BtChannel_Tests.h"
#include "tests_cryptoTools/Ecc_Tests.h"
#include "tests_cryptoTools/Misc_Tests.h"
#include "tests_cryptoTools/Cuckoo_Tests.h"


using namespace osuCrypto;

namespace tests_cryptoTools
{
    void run(std::string name, std::function<void(void)> func)
    {
        std::cout << Color::Blue << name << ColorDefault << std::flush;

        auto start = std::chrono::high_resolution_clock::now();
        try
        {
            func(); std::cout << Color::Green << "  Passed" << ColorDefault;
        }
        catch (const std::exception& e)
        {
            std::cout << Color::Red << "Failed - " << e.what() << ColorDefault;
        }

        auto end = std::chrono::high_resolution_clock::now();

        u64 time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "   " << time << "ms" << std::endl;

    }


    void tests_Network_all()
    {

        std::cout << std::endl;
        run("BtNetwork_Connect1_Boost_Test           ", BtNetwork_Connect1_Boost_Test);
        run("BtNetwork_OneMegabyteSend_Boost_Test    ", BtNetwork_OneMegabyteSend_Boost_Test);
        run("BtNetwork_ConnectMany_Boost_Test        ", BtNetwork_ConnectMany_Boost_Test);
        run("BtNetwork_CrossConnect_Test             ", BtNetwork_CrossConnect_Test);
        run("BtNetwork_ManyEndpoints_Test            ", BtNetwork_ManyEndpoints_Test);
        run("BtNetwork_bitVector_Test                ", BtNetwork_bitVector_Test);
        run("BtNetwork_AsyncConnect_Boost_Test();    ", BtNetwork_AsyncConnect_Boost_Test);
        run("BtNetwork_std_Containers_Test();        ", BtNetwork_std_Containers_Test);
        run("BtNetwork_recvErrorHandler_Test();      ", BtNetwork_recvErrorHandler_Test);
        run("BtNetwork_closeOnError_Test();          ", BtNetwork_closeOnError_Test);
    }

    void tests_bitVec_all()
    {
        std::cout << std::endl;
        run("AES                                     ", AES_EncDec_Test);

        std::cout << std::endl;
        run("BitVector_Indexing_Test                 ", BitVector_Indexing_Test_Impl);
        run("BitVector_Parity                        ", BitVector_Parity_Test_Impl);
        run("BitVector_Append_Test                   ", BitVector_Append_Test_Impl);
        run("BitVector_Copy_Test                     ", BitVector_Copy_Test_Impl);

        std::cout << std::endl;
        run("CuckooHasher_many_Test_Impl             ", CuckooHasher_many_Test_Impl);
        run("CuckooHasher_paramSweep_Test_Impl       ", CuckooHasher_paramSweep_Test_Impl);
        run("CuckooHasher_parallel_Test_Impl         ", CuckooHasher_parallel_Test_Impl);
        run("CuckooMap_Big_Test_Impl                  ", CuckooMap_Big_Test_Impl);
    }


    void tests_Ecc_all()
    {
        std::cout << std::endl;

        run("Ecc2mNumber_Test                        ", Ecc2mNumber_Test);
        run("Ecc2mPoint_Test                         ", Ecc2mPoint_Test);
        run("EccpNumber_Test                         ", EccpNumber_Test);
        run("EccpPoint_Test                          ", EccpPoint_Test);

    }


    void tests_all()
    {
        tests_Network_all();
        tests_bitVec_all();
        tests_Ecc_all();
    }
}