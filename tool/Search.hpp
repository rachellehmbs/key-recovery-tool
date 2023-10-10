#ifndef SEARCH_HPP
#define SEARCH_HPP

#include "Solver.hpp"
#include "Cipher.hpp"

Solver searchBestSolver(Cipher c, double bound_time, double bound_mem, double bound_off);
std::vector<Solver> generateBaseAndKeySolversSpecial(Cipher c) ;

#endif
