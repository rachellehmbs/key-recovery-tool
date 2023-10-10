#ifndef CIPHER_HPP
#define CIPHER_HPP

#include <cstdio>
#include <fstream>
#include <math.h>
#include <stdlib.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <iterator>
#include <cassert>
#include <string.h>
#include <algorithm>
#include <iomanip>

#include "Matrix.hpp"



class Cipher{
    public :
    Cipher() {};
    Cipher(std::ifstream &input_file, double N, bool be_slow = false); // N = number of plaintexts pairs

    Cipher(Cipher const &) = default;
    Cipher(Cipher &&) = default;

    Cipher & operator=(Cipher const &) = default;
    Cipher & operator=(Cipher &&) = default;

    void getKS(std::ifstream &input_file);
    void computeDDT();

    void propagation();
    std::vector <unsigned> getDiff(unsigned i, unsigned j, std::vector <unsigned> & prop) const;

    unsigned findBitsToZeroForward(std::vector < unsigned > din) const;
    unsigned findBitsToOneForward(std::vector < unsigned > din) const;
    unsigned findBitsToZeroBackward(std::vector < unsigned > dout) const;
    unsigned findBitsToOneBackward(std::vector < unsigned > dout) const;
    void fillSb();
    unsigned getNrSol(std::vector <unsigned> vectDin, std::vector < unsigned > vectDout);
    std::vector < unsigned > possibleVectors( std::vector < unsigned> vect ) const;

    //ACCESSORS
    //SB
    unsigned getSizeSB() const {return sizeSB;};
    unsigned getLenSB() const {return lenSB;};
    unsigned getNrSB() const {return nrSB;};
    std::vector<unsigned> const & getSB() const {return SB;};
    std::vector<std::vector<unsigned>> const & getDDT() const {return DDT;};
    //PERM
    unsigned getSizeBlock() const {return sizeBlock;};
    std::vector<unsigned> const & getPERM() const {return PERM;};
    std::vector<unsigned> const & getPERMinv() const {return InvPERM;};
    //nrR
    unsigned getNrR() const {return nrR;};
    //DIFF
    std::vector<unsigned> const & getDINa() const {return DINa;};
    std::vector<unsigned> const & getDOUTa() const {return DOUTa;};
    std::vector<unsigned> const & getDINb() const {return DINb;};
    std::vector<unsigned> const & getDOUTb() const {return DOUTb;};
    unsigned getNrSBp() const {return nrSBp;};
    unsigned getNrSBc() const {return nrSBc;};
    //KS
    std::vector<std::vector<unsigned>> const & getKS() const {return KS;};
    //Other
    double getNpairs() const {return Npairs;};
    double nbsol(unsigned s) const {return solSboxes[s];}; // return the number of solutions for Sbox s
    Matrix & matrixKS() {return matKS;};
    unsigned activityBitBeforeSB(unsigned b) const {return prop[(b/sizeBlock)*2*sizeBlock+(b%sizeBlock)];};
    unsigned activityBitAfterSB(unsigned b) const  {return prop[((b/sizeBlock)*2+1)*sizeBlock+(b%sizeBlock)];};
    unsigned activitySB(unsigned sb) const {return activitySBT[sb];};
    friend std::ostream& operator<<(std::ostream &, Cipher const &); //overload print

    std::vector<unsigned> getRelatedSboxes(unsigned x) const {return relatedSboxes[x];};

    double getFilter(unsigned sb) const {return filterSB[sb];};

    void resizeMat(std::vector<unsigned> const & v) {matKS = matKS.extract(v);};

    bool isKnownKeyBit(unsigned b) {return knownkeybits[b] == 1;};
    double nbSolsIn(unsigned s) const {return solSboxesIn[s];}; // return the number of solutions for Sbox s

    void setNpairs(double p) {Npairs = p;};

    int global_ct;

    private :

    bool beslow;

    //SB
    unsigned sizeSB;
    unsigned lenSB;
    unsigned nrSB;
    std::vector<unsigned> SB;
    std::vector<std::vector<unsigned>> DDT;
    double Npairs; //number of plaintext pairs (log2)

    //PERM and InvPERM
    unsigned sizeBlock;
    std::vector<unsigned> PERM;
    std::vector<unsigned> InvPERM;

    //nrR
    unsigned nrR;

    //DIFF
    unsigned nrSBp;
    unsigned nrSBc;
    std::vector<unsigned> prop;
    std::vector<unsigned> DINb;
    std::vector<unsigned> DINa;
    std::vector<unsigned> DOUTb;
    std::vector<unsigned> DOUTa;
    std::vector<unsigned> DKEY;

    //KS
    std::vector<std::vector<unsigned>> KS;

    //nbsols
    std::vector<double> solSboxes; //contains the number of solutions for each sbox

    //activity bit before Sbox
    std::vector<unsigned> activityBitBSB; //contains for a bit b of the state before an Sbox, the value of the bit (0, 1 or 2)

    std::vector<unsigned> activityBitASB; //contains for a bit b of the state after an Sbox, the value of the bit (0, 1 or 2)

std::vector<unsigned> activitySBT; //contains for each Sbox a value 0, 1, whether the Sbox is active or passive.
     std::vector<double> filterSB;

    //Matrix KS
    Matrix matKS;

    std::vector<std::vector<unsigned>> relatedSboxes;

    std::vector<uint8_t> knownkeybits;
    //nbsols
    std::vector<double> solSboxesIn; //contains the number of solutions for each sbox

};

#endif
