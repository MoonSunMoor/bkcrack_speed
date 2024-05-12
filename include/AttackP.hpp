#ifndef BKCRACK_ATTACKP_HPP
#define BKCRACK_ATTACKP_HPP

#include "Attack.hpp"

#include "Data.hpp"
#include "Keys.hpp"
#include "Progress.hpp"
#include "types.hpp"


typedef std::uint32_t KeyPack[8];
struct KeySet
{
    KeyPack z;  // the first two bits are not used -> first bit a vaild flag
    KeyPack y;  // the first two elements are not used
    KeyPack x;  // the first four elements are not used -> [0] is for x in compute
};


/// \file AttackP.hpp

/// Class to carry out the attack for a given Z[2,32) value
class AttackP : public Attack
{
public:
    void testXlist(std::vector<KeySet> keypacks);
};
#endif // BKCRACK_ATTACKP_HPP