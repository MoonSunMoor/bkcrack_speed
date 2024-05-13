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

    void carryout(std::uint32_t z7_2_32);

    void expandZlist(int i);
    void compactZlist();
    void exploreZlists();
    void exploreZlists(int i);  // Temporary warper

    void propagateYlist();

    void expandYlist(int i);
    void compactYlist();
    void exploreYlists();
    void exploreYlists(int i);  // Temporary warper

    void testXlist();

    AttackP(const Data& data, std::size_t index, std::vector<Keys>& solutions, std::mutex& solutionsMutex,
            bool exhaustive, Progress& progress);
protected:
    KeyPack extractKeyPack();


    std::vector<KeyPack> keypacks;
};
#endif // BKCRACK_ATTACKP_HPP