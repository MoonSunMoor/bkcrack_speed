#ifndef BKCRACK_ATTACKP_HPP
#define BKCRACK_ATTACKP_HPP

#include "Attack.hpp"

#include "Data.hpp"
#include "Keys.hpp"
#include "Progress.hpp"
#include "types.hpp"


typedef std::uint32_t KeyList[8];
struct KeyPack
{
    KeyList z;  // the first two bits are not used -> first bit a vaild flag
    KeyList y;  // the first two elements are not used
    KeyList x;  // the first four elements are not used -> [0] is for x in compute
};


/// \file AttackP.hpp

/// Class to carry out the attack for a given Z[2,32) value
class AttackP : public Attack
{
public:
    void exploreYlists(int i);
    void testXlist();

    AttackP(const Data& data, std::size_t index, std::vector<Keys>& solutions, std::mutex& solutionsMutex,
            bool exhaustive, Progress& progress);
protected:
    std::vector<KeyPack> keypacks;
};
#endif // BKCRACK_ATTACKP_HPP