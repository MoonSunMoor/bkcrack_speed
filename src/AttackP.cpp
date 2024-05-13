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


void AttackP::expandZlist(int i) {
    int                  idx = 0;
    std::vector<KeyPack> buffer(keypacks.size() * 5); // TODO

    std::for_each(
        keypacks.begin(), keypacks.end(), 
        [&](auto key) 
        {
            int local_idx = 0;
            // get Z{i-1}[10,32) from CRC32^-1
            const auto zim1_10_32 = Crc32Tab::getZim1_10_32(key.z[i]);
            const auto zi_2_16_v = KeystreamTab::getZi_2_16_vector(data.keystream[index + i - 1], zim1_10_32);

            for (const auto zim1_2_16 : zi_2_16_v)
            {
                key.z[0] |= 1; // Mark as vaild
                          
                // add Z{i-1}[2,32) to the Z-list
                key.z[i - 1] = zim1_10_32 | zim1_2_16;
                          
                key.z[i] &= mask<2, 32>; // discard 2 least significant bits
                key.z[i] |= (Crc32Tab::crc32inv(key.z[i], 0) ^ key.z[i - 1]) >> 8;

                buffer[idx * 5 + local_idx] = key;
                idx++;
                local_idx++;
            }
        });
    keypacks = buffer;
}

void Attack::exploreZlists(int i)
{
    if (i != 0) // the Z-list is not complete so generate Z{i-1}[2,32) values
    {
        // get Z{i-1}[10,32) from CRC32^-1
        const auto zim1_10_32 = Crc32Tab::getZim1_10_32(zlist[i]);

        // get Z{i-1}[2,16) values from keystream byte k{i-1} and Z{i-1}[10,16)
        for (const auto zim1_2_16 : KeystreamTab::getZi_2_16_vector(data.keystream[index + i - 1], zim1_10_32))
        {
            // add Z{i-1}[2,32) to the Z-list
            zlist[i - 1] = zim1_10_32 | zim1_2_16;

            // find Zi[0,2) from CRC32^1
            zlist[i] &= mask<2, 32>; // discard 2 least significant bits
            zlist[i] |= (Crc32Tab::crc32inv(zlist[i], 0) ^ zlist[i - 1]) >> 8;

            // get Y{i+1}[24,32)
            if (i < 7)
                ylist[i + 1] = Crc32Tab::getYi_24_32(zlist[i + 1], zlist[i]);

            exploreZlists(i - 1);
        }
    }
    else // the Z-list is complete so iterate over possible Y values
    {
        // guess Y7[8,24) and keep prod == (Y7[8,32) - 1) * mult^-1
        for (auto y7_8_24 = std::uint32_t{}, prod = (MultTab::getMultinv(msb(ylist[7])) << 24) - MultTab::multInv;
             y7_8_24 < 1 << 24; y7_8_24 += 1 << 8, prod += MultTab::multInv << 8)
            // get possible Y7[0,8) values
            for (const auto y7_0_8 : MultTab::getMsbProdFiber3(msb(ylist[6]) - msb(prod)))
                // filter Y7[0,8) using Y6[24,32)
                if (prod + MultTab::getMultinv(y7_0_8) - (ylist[6] & mask<24, 32>) <= maxdiff<24>)
                {
                    ylist[7] = y7_0_8 | y7_8_24 | (ylist[7] & mask<24, 32>);
                    exploreYlists(7);
                }
    }
}


void AttackP::expandYlist(int i)
{
    int                  global_idx = 0;
    std::vector<KeyPack> buffer(keypacks.size() * 5);

    std::for_each(keypacks.begin(), keypacks.end(),
                  [&](auto key)
                  {
                      int local_idx = 0;

                      const auto fy  = (key.y[i] - 1) * MultTab::multInv;
                      const auto ffy = (fy - 1) * MultTab::multInv;

                      // get possible LSB(Xi)
                      for (const auto xi_0_8 : MultTab::getMsbProdFiber2(msb(ffy - (key.y[i - 2] & mask<24, 32>))))
                      {
                          // compute corresponding Y{i-1}
                          const auto yim1 = fy - xi_0_8;

                          // filter values with Y{i-2}[24,32)
                          if (ffy - MultTab::getMultinv(xi_0_8) - (key.y[i - 2] & mask<24, 32>) <= maxdiff<24> &&
                              msb(yim1) == msb(key.y[i - 1]))
                          {
                              // add Y{i-1} to the Y-list
                              key.y[i - 1] = yim1;

                              // set Xi value
                              key.x[i] = xi_0_8;

                              // Set as vaild
                              key.y[0] = -1;

                              buffer[global_idx * 5 + local_idx] = key;
                              global_idx++;
                              local_idx++;
                          }
                      }
                  });
    keypacks = buffer;
}

void AttackP::compactYlist() {
    keypacks.erase(std::remove_if(
        keypacks.begin(), keypacks.end(),
        [&](const auto e) { 
            return e.y[0] == 0;
        }));
}

// TODO: Parallelize
void AttackP::exploreYlists(int i)
{
    KeyPack cur_list;
    memcpy(cur_list.x, xlist.data(), 8);
    memcpy(cur_list.y, ylist.data(), 8);
    memcpy(cur_list.z, zlist.data(), 8);
    keypacks.push_back(cur_list);

    // Only for testing. Breaks --continue-attack and more
    if (keypacks.size() > 1024)
        exploreYlists();
}

void AttackP::exploreYlists()
{
    for (int k = 7; k > 3; k++)
    {
        expandYlist(k);
        compactYlist();
    }
    std::cout << keypacks.size() << "\n";
    // the Y-list is complete so add key list for pending if x is vaild
    if (keypacks.size() > 1024)
        testXlist();
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
