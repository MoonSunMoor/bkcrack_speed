#include "AttackP.hpp"

#include "Crc32Tab.hpp"
#include "KeystreamTab.hpp"
#include "MultTab.hpp"
#include "log.hpp"

#include <algorithm>
#include <string>

AttackP::AttackP(const Data& data, std::size_t index, std::vector<Keys>& solutions, std::mutex& solutionsMutex,
               bool exhaustive, Progress& progress)
: Attack(data, index, solutions, solutionsMutex, exhaustive, progress)
{
}

// TODO: Parallelize
void AttackP::exploreYlists(int i)
{
    if (i != 3) // the Y-list is not complete so generate Y{i-1} values
    {
        const auto fy  = (ylist[i] - 1) * MultTab::multInv;
        const auto ffy = (fy - 1) * MultTab::multInv;

        // get possible LSB(Xi)
        for (const auto xi_0_8 : MultTab::getMsbProdFiber2(msb(ffy - (ylist[i - 2] & mask<24, 32>))))
        {
            // compute corresponding Y{i-1}
            const auto yim1 = fy - xi_0_8;

            // filter values with Y{i-2}[24,32)
            if (ffy - MultTab::getMultinv(xi_0_8) - (ylist[i - 2] & mask<24, 32>) <= maxdiff<24> &&
                msb(yim1) == msb(ylist[i - 1]))
            {
                // add Y{i-1} to the Y-list
                ylist[i - 1] = yim1;

                // set Xi value
                xlist[i] = xi_0_8;

                exploreYlists(i - 1);
            }
        }
    }
    else // the Y-list is complete so add key list for pending if x is vaild
    {
        KeyPack cur_list;
        memcpy(cur_list.x, xlist.data(), 8);
        memcpy(cur_list.y, ylist.data(), 8);
        memcpy(cur_list.z, zlist.data(), 8);
        keypacks.push_back(cur_list);

        if (keypacks.size() > 64)
            testXlist();
    }
}


// Parallelized with CUDA in mind
void AttackP::testXlist()
{
    std::for_each(
        keypacks.begin(), keypacks.end(),
        [&](auto& keys)
        {
            // compute X7
            for (auto i = 5; i <= 7; i++)
                keys.x[i] = (Crc32Tab::crc32(keys.x[i - 1], data.plaintext[index + i - 1]) & mask<8, 32>)     // discard the LSB
                    | lsb(keys.x[i]); // set the LSB

            // compute X3
            auto& x = keys.x[0];
            x       = keys.x[7];
            for (auto i = 6; i >= 3; i--)
                x = Crc32Tab::crc32inv(x, data.plaintext[index + i]);
        });

    // check that X3 fits with Y1[26,32)
    keypacks.erase(std::remove_if(
        keypacks.begin(), keypacks.end(),
        [&](const auto e)
        {        
            const auto& x        = e.x[0];
            const auto  y1_26_32 = Crc32Tab::getYi_24_32(e.z[1], e.z[0]) & mask<26, 32>;
            return ((ylist[3] - 1) * MultTab::multInv - lsb(x) - 1) * MultTab::multInv - y1_26_32 > maxdiff<26>;
        }));


    // decipher and filter by comparing with remaining contiguous plaintext forward
    keypacks.erase(std::remove_if(
        keypacks.begin(), keypacks.end(),
        [&](const auto e)
        {
            auto keysForward = Keys{e.x[7], e.y[7], e.z[7]};
            keysForward.update(data.plaintext[index + 7]);
            for (auto p = data.plaintext.begin() + index + 8,
                c = data.ciphertext.begin() + data.offset + index + 8;
                p != data.plaintext.end(); ++p, ++c)
            {
                if((*c ^ keysForward.getK()) != *p)
                    return true;
                keysForward.update(*p);
            }    
            return false;
        }));
    auto indexForward = data.offset + data.plaintext.size();


    // and also backward
    keypacks.erase(std::remove_if(
        keypacks.begin(), keypacks.end(),
        [&](const auto e)
        {
            auto keysBackward = Keys{e.x[0], e.y[3], e.z[3]};
            for (auto p = std::reverse_iterator{data.plaintext.begin() + index + 3},
                c = std::reverse_iterator{data.ciphertext.begin() + data.offset + index + 3};
                p != data.plaintext.rend(); ++p, ++c)
            {
                keysBackward.updateBackward(*c);
                if ((*c ^ keysBackward.getK()) != *p)
                    return true;
            }
            return false;
        }));
    auto indexBackward = data.offset;


    // TODO: implement extra known plaintext filter (likely to do in forward, backward filiter)
    /*
    // continue filtering with extra known plaintext
    for (const auto& [extraIndex, extraByte] : data.extraPlaintext)
    {
        auto p = std::uint8_t{};
        if (extraIndex < indexBackward)
        {
            keysBackward.updateBackward(data.ciphertext, indexBackward, extraIndex);
            indexBackward = extraIndex;
            p             = data.ciphertext[indexBackward] ^ keysBackward.getK();
        }
        else
        {
            keysForward.update(data.ciphertext, indexForward, extraIndex);
            indexForward = extraIndex;
            p            = data.ciphertext[indexForward] ^ keysForward.getK();
        }

        if (p != extraByte)
            return;
    }
    */

    // all tests passed so the keys are found

    // End of parallel action

    if (keypacks.empty())
        return;

    // get the keys associated with the initial state
    std::vector<Keys> solutionKeys;
    std::for_each(keypacks.begin(), keypacks.end(),
        [&](const auto& e)
        {
            auto keysBackward = Keys{e.x[0], e.y[3], e.z[3]};
            keysBackward.updateBackward(data.ciphertext, indexBackward + index + 3, 0);
        });

    keypacks.clear();

    {
        const auto lock = std::scoped_lock{solutionsMutex};
        std::for_each(solutionKeys.begin(), solutionKeys.end(), 
            [this](const auto& e) 
            { 
                solutions.push_back(e); 
                progress.log([&e](std::ostream& os)
                                       { os << "Keys: " << e << std::endl; });
            });
    }
    
    if (!exhaustive)
        progress.state = Progress::State::EarlyExit;
}
