#ifndef SOLVER_HPP
#define SOLVER_HPP

#include <vector>
#include <iostream>
#include <memory>

#include "Cipher.hpp"

class Solver {
public:
    Solver(); // construct the solver for plaintext/ciphertext and set the number of solutions to N, say it corresponds to sbox 0
    Solver(unsigned sb, bool fromP, bool isKey); //construct the solver for sbox sb

    Solver (Solver const &) = default;
    Solver (Solver &&) = default;

    Solver & operator=(Solver const &) = default;
    Solver & operator=(Solver &&) = default;

    ~Solver() = default;

    static void setCipher(Cipher c) {cipher = std::move(c);};
    static Cipher & getCipher() {return cipher;};
    static void resizeMat(std::vector<unsigned> const & v) {cipher.resizeMat(v);};

    friend std::ostream& operator<<(std::ostream &, Solver const &); //overload print

    friend Solver merge(Solver const & s1, Solver const & s2); // merge 2 solvers
    // si s1 et s2 contiennent P/C: time_on = max(nbsols, s1.time_on, s2.time_on), time_off = max(s1.time_off, s2.time_off),
    //     memory = max(s1.memory, s2.memory, min(s1.nbsols, s2.nbsols))
    // si s1 contient P/C et pas s2: time_on = max(nbsols, s1.time_on), time_off = max(s1.time_off, s2.time_off),
    //     memory = max(s1.memory, s2.memory, s2.nbsols)
    // si s1 et s2 ne contiennent pas P/C:  time_on = 0, time_off = max(nbsols, s1.time_off, s2.time_off),
    //     memory = max(s1.memory, s2.memory, min(s1.nbsols, s2.nbsols))

    friend Solver mergePrint(Solver const & s1, Solver const & s2);

    friend bool isBetter(Solver const & s1, Solver const & s2);
    friend bool isBetterNoMem(Solver const & s1, Solver const & s2);
    friend bool isFaster(Solver const & s1, Solver const & s2);
    friend bool isBetterS(Solver const & s1, Solver const & s2, double t);

    friend double nbSolsInt(Solver const & s1, Solver const & s2);

    friend Solver refine(Solver const & s);

    friend Solver findCommon(std::vector<std::shared_ptr<Solver>> & v);

    std::vector<unsigned> getKeyBits() const;

    std::vector<unsigned> const & sboxesFromP() const {return sboxesP;};
    std::vector<unsigned> const & sboxesFromC() const {return sboxesC;};

    bool isSbox() const {return sboxesP.size() == 1 || sboxesC.size() == 1;};

    bool dependOnPC() const {return PC;};

    void printKeyBits();

    unsigned & getDST() {return dst;};
    unsigned getDST() const {return dst;};

    unsigned nbVars() const {return sboxesP.size() + sboxesC.size() + sboxesP_in.size() + sboxesC_in.size();};
    unsigned nbStateVars() const {return sboxesP.size() + sboxesC.size();};

    double timeON() const {return time_on;};
    double nbSols() const {return nbsols;};
    double timeOFF() const {return time_off;};
    double mem() const {return memory;};
    double isPC() const {return PC;};

    void setTimeToSol() {time_on = nbsols;};

    void printSolver() const;

    std::size_t id() const;



private:
    std::vector<unsigned> sboxesP; // indexes of sboxes handled by the solver
    std::vector<unsigned> sboxesC; // indexes of sboxes handled by the solver
    std::vector<unsigned> sboxesP_in; // indexes of sboxes handled by the solver
    std::vector<unsigned> sboxesC_in; // indexes of sboxes handled by the solver
    bool PC;
    double time_on;
    double time_off;
    double memory;
    double nbsols;

    // smart pointers for the tree
    std::shared_ptr<Solver> node1;
    std::shared_ptr<Solver> node2;

    unsigned dst;


    static Cipher cipher;
};

void printSolverInFile(const char *filename, Solver mySolver);

#endif
