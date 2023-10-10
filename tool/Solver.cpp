#include <functional>
#include <set>
#include "Solver.hpp"

using namespace std;

Solver::Solver() : PC (true), time_on (cipher.getNpairs()), time_off (0.), memory (0.), nbsols (time_on), node1 (nullptr), node2 (nullptr) {
  dst = 3;
}

Solver::Solver (unsigned sb, bool fromP, bool in) : PC (false), time_on (0.), memory (0.), node1 (nullptr), node2 (nullptr) {
    if (!in){
        time_off = cipher.nbsol(sb);
        nbsols = time_off;
        if (fromP) {
          sboxesP.emplace_back(sb);
          dst = 1;
        }
        else {
          sboxesC.emplace_back(sb);
          dst = 2;
        }
    }
    else {
        //time_off = 1 - Solver::cipher.matrixKS().computeRank(keys, true); //0 if known key bit, 1 otherwise
        time_off = cipher.nbSolsIn(sb);
        nbsols = time_off;
        if (fromP) {
          sboxesP_in.emplace_back(sb);
          dst = 1;
        }
        else {
          sboxesC_in.emplace_back(sb);
          dst = 2;
        }
    }
}

void Solver::printSolver() const{
    cout << endl;

    cout << "plaintext : ";
    for (int i = 0; i < sboxesP.size(); i++)
        cout << sboxesP[i] << " ";
    if (sboxesP_in.size() > sboxesP.size()) {
      cout << "(";
      for (auto const & x : sboxesP_in) if (!binary_search(sboxesP.begin(), sboxesP.end(), x)) cout << x << " ";
      cout << ")";
    }
    cout << endl;

    cout << "ciphertext : ";
    for (int i = 0; i < sboxesC.size(); i++)
        cout << sboxesC[i] << " ";
    if (sboxesC_in.size() > sboxesC.size()) {
      cout << "(";
      for (auto const & x : sboxesC_in) if (!binary_search(sboxesC.begin(), sboxesC.end(), x)) cout << x << " ";
      cout << ")";
    }
    cout << endl;

    cout << "nr sols : " << nbsols << endl;
    cout << "time online : " << time_on << endl;
    cout << "time offline : "<< time_off << endl;
    cout << "memory : " << memory << endl;
    cout << "is PC : "<< PC << endl;

    cout << endl;

}

vector<unsigned> Solver::getKeyBits() const {
  vector<unsigned> mykey;


  unsigned const & nbbitssbox = cipher.getLenSB(); //Speedy : 6
  unsigned const & nbbits = cipher.getSizeBlock(); //Speedy : 192
  unsigned const & nbsboxes = nbbits/nbbitssbox; //Speedy : 32


  for (auto s : sboxesP_in) { //for each SB
      unsigned r = s / nbsboxes; //round of the SB (round r) // r = 1
      unsigned i = s % nbsboxes; //index of the SB in its round (SB n°i) //i = 3
      unsigned b = i*nbbitssbox; //index of the first bit of the SB in its round (b = bit 0 of SB n°i)
      unsigned k = r*nbbits + b; //index of the first bit of the SB overall (b = bit 0 of SB n°i of round r)

      bool flag_full_sbox = binary_search(sboxesP.begin(), sboxesP.end(), s);

      for (unsigned l = 0; l < nbbitssbox; ++l) {
          if (r == 0) { //if first round (the value of the pair is known everywhere since the plaintext is known)
              if (PC) { //if merging at least one cipher that has the number of pairs
                            //divide by the nr of possible pairs
                  if (flag_full_sbox) {
                    mykey.emplace_back(k+l);
                  }
                  //if (binary_search(keys.begin(), keys.end(), k+l)) nbsols -= 1; //key bit is known
                                                                                             // if both are true then there are 2^2 pairs of values possible on this bit
              }
          }
          else {
              auto j = (r-1)*nbsboxes + cipher.getPERMinv()[b+l] / nbbitssbox; //ok //j takes as value the index of the SB which influenced the l^th bit of the SB
                                                                               //cout << j << endl;
              if (binary_search(sboxesP.begin(), sboxesP.end(), j)) { //in other words, if the lth bit of the SB has already been guessed/fixed, ie the value of the pair on this bit is guessed/fixed
                  //if (binary_search(keys.begin(), keys.end(), k+l)) nbsols -= 1; //key bit is known
                  if (flag_full_sbox) {
                    mykey.emplace_back(k+l);
                  }

              }
          }
      }
  }

  for (auto s : sboxesC_in) {
      unsigned r = s / nbsboxes;
      unsigned i = s % nbsboxes;
      unsigned b = i*nbbitssbox;

      bool flag_full_sbox = binary_search(sboxesC.begin(), sboxesC.end(), s);
      for (unsigned l = 0; l < nbbitssbox; ++l) {
          if (r == cipher.getNrR()-1) {
              if (PC) {
                  if (flag_full_sbox) {
                    mykey.emplace_back(cipher.getPERM()[b+l] + (r+1)*nbbits);
                  }

              }
          }
          else {
              auto j = (r+1)*nbsboxes + cipher.getPERM()[b+l] / nbbitssbox;  //j takes as value the index of the SB which influenced the l^th bit of the SB
              if (binary_search(sboxesC.begin(), sboxesC.end(), j)) { // if the lth bit of the SB has already been guessed/fixed, ie the value of the pair on this bit is guessed/fixed
                  if (flag_full_sbox) {
                    mykey.emplace_back(cipher.getPERM()[b+l] + (r+1)*nbbits);
                  }
              }
          }
      }
  }
  sort(mykey.begin(), mykey.end());

  return mykey;
}

double computeNbsol(vector<unsigned> const & sboxesP, vector<unsigned> const & sboxesC, vector<unsigned> const & sboxesP_in, vector<unsigned> const & sboxesC_in, bool PC, Cipher & cipher){
        //compute number of solutions
    double nbsols = 0.0;
    for (auto s : sboxesP) nbsols += cipher.nbsol(s);
    for (auto s : sboxesC) nbsols += cipher.nbsol(s);
    for (auto s : sboxesP_in) nbsols += cipher.nbSolsIn(s);
    for (auto s : sboxesC_in) nbsols += cipher.nbSolsIn(s);
    if (PC) { //If we're considering at least a solver that solves w/ a number of pairs
        nbsols += cipher.getNpairs();
    }

    vector<unsigned> mykey;


    unsigned const & nbbitssbox = cipher.getLenSB();
    unsigned const & nbbits = cipher.getSizeBlock();
    unsigned const & nbsboxes = nbbits/nbbitssbox;


    for (auto s : sboxesP_in) { //for each SB
        unsigned r = s / nbsboxes; //round of the SB (round r)
        unsigned i = s % nbsboxes; //index of the SB in its round (SB n°i)
        unsigned b = i*nbbitssbox; //index of the first bit of the SB in its round (b = bit 0 of SB n°i)
        unsigned k = r*nbbits + b; //index of the first bit of the SB overall (b = bit 0 of SB n°i of round r)

        bool flag_full_sbox = binary_search(sboxesP.begin(), sboxesP.end(), s);

        if (flag_full_sbox) nbsols -= cipher.nbSolsIn(s) + cipher.getFilter(s);

        for (unsigned l = 0; l < nbbitssbox; ++l) {
            if (r == 0) { //if first round (the value of the pair is known everywhere since the plaintext is known)
                if (PC) { //if merging at least one cipher that has the number of pairs
                              //divide by the nr of possible pairs
                    if (cipher.activityBitBeforeSB(k+l) == 2) nbsols -= 1; //diff on the bit is not fixed before the SB
                    if (cipher.isKnownKeyBit(k+l)) nbsols -= 1;
                    else if (flag_full_sbox) {
                      nbsols -= 1;
                      mykey.emplace_back(k+l);
                    }
                }
            }
            else {
                auto j = (r-1)*nbsboxes + cipher.getPERMinv()[b+l] / nbbitssbox;
                if (binary_search(sboxesP.begin(), sboxesP.end(), j)) { //in other words, if the lth bit of the SB has already been guessed/fixed, ie the value of the pair on this bit is guessed/fixed
                    if (cipher.activityBitBeforeSB(k + l) == 2) nbsols -= 1; //diff on the bit is not fixed before the SB
                    if (cipher.isKnownKeyBit(k+l)) nbsols -= 1;
                    else if (flag_full_sbox) {
                      nbsols -= 1;
                      mykey.emplace_back(k+l);
                    }

                }
            }
        }
    }

    for (auto s : sboxesC_in) {
        unsigned r = s / nbsboxes;
        unsigned i = s % nbsboxes;
        unsigned b = i*nbbitssbox;

        bool flag_full_sbox = binary_search(sboxesC.begin(), sboxesC.end(), s);

        if (flag_full_sbox) nbsols -= cipher.nbSolsIn(s) + cipher.getFilter(s);

        for (unsigned l = 0; l < nbbitssbox; ++l) {
            if (r == cipher.getNrR()-1) {
                if (PC) {
                    if (cipher.activityBitAfterSB(r*nbbits + b+l) == 2) nbsols -= 1;
                    if (cipher.isKnownKeyBit(cipher.getPERM()[b+l] + (r+1)*nbbits)) nbsols -= 1;
                    else if (flag_full_sbox) {
                      nbsols -= 1;
                      mykey.emplace_back(cipher.getPERM()[b+l] + (r+1)*nbbits);
                    }


                }
            }
            else {
                auto j = (r+1)*nbsboxes + cipher.getPERM()[b+l] / nbbitssbox; //j takes as value the index of the SB which influenced the l^th bit of the SB
                if (binary_search(sboxesC.begin(), sboxesC.end(), j)) { //in other words, if the lth bit of the SB has already been guessed/fixed, ie the value of the pair on this bit is guessed/fixed
                    if (cipher.activityBitAfterSB(r*nbbits + b+l) == 2) nbsols -= 1;
                    if (cipher.isKnownKeyBit(cipher.getPERM()[b+l] + (r+1)*nbbits)) nbsols -= 1;
                    else if (flag_full_sbox) {
                      nbsols -= 1;
                      mykey.emplace_back(cipher.getPERM()[b+l] + (r+1)*nbbits);
                    }
                }
            }
        }
    }
    sort(mykey.begin(), mykey.end());

    nbsols += mykey.size();
    nbsols -= cipher.matrixKS().computeRank(mykey, true); //dim of key material


    return nbsols;
}

Solver merge(Solver const & s1, Solver const & s2) {
        // merge 2 solvers
        // si s1 et s2 contiennent P/C: time_on = max(nbsols, s1.time_on, s2.time_on), time_off = max(s1.time_off, s2.time_off),
        //     memory = max(s1.memory, s2.memory, min(s1.nbsols, s2.nbsols))
        // si s1 contient P/C et pas s2: time_on = max(nbsols, s1.time_on), time_off = max(s1.time_off, s2.time_off),
        //     memory = max(s1.memory, s2.memory, s2.nbsols)
        // si s1 et s2 ne contiennent pas P/C:  time_on = 0, time_off = max(nbsols, s1.time_off, s2.time_off),
        //     memory = max(s1.memory, s2.memory, min(s1.nbsols, s2.nbsols))
    auto & cipher = Solver::getCipher();
    Solver res;

        //vectors containing the SBs' indexes is created and set to the union of the indexes (both for the plaintext and ciphertext side)
        //plaintext
    res.sboxesP = vector<unsigned> (s1.sboxesP.size() + s2.sboxesP.size());
    auto it = set_union (s1.sboxesP.begin(), s1.sboxesP.end(), s2.sboxesP.begin(), s2.sboxesP.end(), res.sboxesP.begin());
    res.sboxesP.resize(it - res.sboxesP.begin());
        //ciphertext
    res.sboxesC = vector<unsigned> (s1.sboxesC.size() + s2.sboxesC.size());
    it = set_union (s1.sboxesC.begin(), s1.sboxesC.end(), s2.sboxesC.begin(), s2.sboxesC.end(), res.sboxesC.begin());
    res.sboxesC.resize(it - res.sboxesC.begin());

    res.sboxesP_in = vector<unsigned> (s1.sboxesP_in.size() + s2.sboxesP_in.size());
    it = set_union (s1.sboxesP_in.begin(), s1.sboxesP_in.end(), s2.sboxesP_in.begin(), s2.sboxesP_in.end(), res.sboxesP_in.begin());
    res.sboxesP_in.resize(it - res.sboxesP_in.begin());
        //ciphertext
    res.sboxesC_in = vector<unsigned> (s1.sboxesC_in.size() + s2.sboxesC_in.size());
    it = set_union (s1.sboxesC_in.begin(), s1.sboxesC_in.end(), s2.sboxesC_in.begin(), s2.sboxesC_in.end(), res.sboxesC_in.begin());
    res.sboxesC_in.resize(it - res.sboxesC_in.begin());
        //key

    res.PC = (s1.PC || s2.PC);

    res.nbsols = computeNbsol(res.sboxesP, res.sboxesC, res.sboxesP_in, res.sboxesC_in, res.PC, cipher);

    if (s1.PC) {
      res.node1 = make_shared<Solver>(s1);
      res.node2 = make_shared<Solver>(s2);
    }
    else {
      res.node1 = make_shared<Solver>(s2);
      res.node2 = make_shared<Solver>(s1);
    }

    if (!s1.PC && !s2.PC) {
        res.time_on = 0.0; //no online time
        res.time_off = max(max(s1.time_off, s2.time_off), res.nbsols);
        res.memory = max(s1.memory, max(s2.memory, min(s1.nbsols, s2.nbsols)));
    }
    else {
        if (s1.PC) {
            if (s2.PC) {
                res.time_on = max(res.nbsols, max(s1.time_on, s2.time_on)); //ok
                res.time_off = max(s1.time_off, s2.time_off);
                vector<shared_ptr<Solver>> v;
                v.emplace_back(res.node1);
                v.emplace_back(res.node2);
                auto common_s = findCommon(v);
                res.memory = max(s1.memory, max(s2.memory, min(s1.nbsols - common_s.nbsols, s2.nbsols - common_s.nbsols)));
            }
            else {
                res.time_on = max(res.nbsols, s1.time_on);
                res.time_off = max(s1.time_off, s2.time_off);
                res.memory = max(s1.memory, max(s2.memory, s2.nbsols));
            }
        }
        else {
            res.time_on = max(res.nbsols, s2.time_on);
            res.time_off = max(s1.time_off, s2.time_off);
            res.memory = max(s1.memory, max(s2.memory, s1.nbsols));
        }
    }


    res.dst = s1.dst & s2.dst;

    if (res.nbsols <= s1.nbsols) res.dst |= s1.dst;
    if (res.nbsols <= s2.nbsols) res.dst |= s2.dst;


    return res;
}


bool isBetter(Solver const & s1, Solver const & s2) {
    if (!s1.PC && s2.PC) return false;
    if (s1.nbsols > s2.nbsols + 0.001) return false;
    if (s1.time_on > s2.time_on + 0.001) return false;
    if (s1.time_off > s2.time_off + 0.001) return false;
    if (s1.memory > s2.memory + 0.001) return false;
    if (!includes(s1.sboxesP.begin(), s1.sboxesP.end(), s2.sboxesP.begin(), s2.sboxesP.end())) return false;
    if (!includes(s1.sboxesC.begin(), s1.sboxesC.end(), s2.sboxesC.begin(), s2.sboxesC.end())) return false;

    if (!includes(s1.sboxesP_in.begin(), s1.sboxesP_in.end(), s2.sboxesP_in.begin(), s2.sboxesP_in.end())) return false;
    if (!includes(s1.sboxesC_in.begin(), s1.sboxesC_in.end(), s2.sboxesC_in.begin(), s2.sboxesC_in.end())) return false;
    return true;
}

bool isBetterNoMem(Solver const & s1, Solver const & s2) {
    if (!s1.PC && s2.PC) return false;
    if (s1.nbsols > s2.nbsols + 0.001) return false;
    if (s1.time_on > s2.time_on + 0.001) return false;
    if (s1.time_off > s2.time_off + 0.001) return false;
    if (!includes(s1.sboxesP.begin(), s1.sboxesP.end(), s2.sboxesP.begin(), s2.sboxesP.end())) return false;
    if (!includes(s1.sboxesC.begin(), s1.sboxesC.end(), s2.sboxesC.begin(), s2.sboxesC.end())) return false;

    if (!includes(s1.sboxesP_in.begin(), s1.sboxesP_in.end(), s2.sboxesP_in.begin(), s2.sboxesP_in.end())) return false;
    if (!includes(s1.sboxesC_in.begin(), s1.sboxesC_in.end(), s2.sboxesC_in.begin(), s2.sboxesC_in.end())) return false;
    return true;
}

bool isBetterS(Solver const & s1, Solver const & s2, double t) {
    if (!s1.PC && s2.PC) return false;
    if (s1.nbsols > s2.nbsols + 0.001) return false;
    if (max(s1.time_on,t) > max(s2.time_on,t) + 0.001) return false;
    if (!includes(s1.sboxesP.begin(), s1.sboxesP.end(), s2.sboxesP.begin(), s2.sboxesP.end())) return false;
    if (!includes(s1.sboxesC.begin(), s1.sboxesC.end(), s2.sboxesC.begin(), s2.sboxesC.end())) return false;
    if (!includes(s1.sboxesP_in.begin(), s1.sboxesP_in.end(), s2.sboxesP_in.begin(), s2.sboxesP_in.end())) return false;
    if (!includes(s1.sboxesC_in.begin(), s1.sboxesC_in.end(), s2.sboxesC_in.begin(), s2.sboxesC_in.end())) return false;
    return true;
}

bool isFaster(Solver const & s1, Solver const & s2) {
    if (s1.time_on != s2.time_on) return s1.time_on < s2.time_on;
    if (s1.nbsols != s2.nbsols) return s1.nbsols < s2.nbsols;
    auto const & u1 = s1.sboxesP.size() + s1.sboxesC.size();
    auto const & u2 = s2.sboxesP.size() + s2.sboxesC.size();
    if (u1 != u2) return u1 > u2;
    auto const & v1 = s1.sboxesP_in.size() + s1.sboxesC_in.size();
    auto const & v2 = s2.sboxesP_in.size() + s2.sboxesC_in.size();
    if (v1 != v2) return v1 > v2;
    if (s1.time_off != s2.time_off) return s1.time_off < s2.time_off;
    return false;
}


size_t Solver::id() const {
  static vector<Solver> mem;
  for (unsigned i = 0; i < mem.size(); ++i) {
    auto const & s = mem[i];
    if (s.sboxesFromP() != sboxesFromP()) continue;
    if (s.sboxesFromC() != sboxesFromC()) continue;
    if (s.sboxesP_in != sboxesP_in) continue;
    if (s.sboxesC_in != sboxesC_in) continue;
    //if (s.keyBits() != keyBits()) continue;
    if (s.PC != PC) continue;
    if (s.time_on != time_on) continue;
    if (s.time_off != time_off) continue;
    if (s.memory != memory) continue;
    return i;
  }
  mem.emplace_back(*this);
  return mem.size() - 1;
}

ostream & operator<<(ostream & flux, Solver const & s) {
    auto & c = Solver::getCipher();
    unsigned const & nbbitssbox = c.getLenSB();
    unsigned const & nbbits = c.getSizeBlock();
    unsigned const & nbsboxes = nbbits/nbbitssbox;

    static set<pair<unsigned, unsigned>> my_set;

    flux << setprecision(2) << fixed;
    int line_return = 0;
    bool isround = 0;

    if (s.PC == 0) {
      flux << "node [label=\"";
      for (auto x : s.sboxesP) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
      if (s.sboxesP_in.size() > s.sboxesP.size()) {
        flux << "(";
        for (auto const & x : s.sboxesP_in) if (!binary_search(s.sboxesP.begin(), s.sboxesP.end(), x)) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
        flux << ")";
      }

      for (auto x : s.sboxesC) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
      if (s.sboxesC_in.size() > s.sboxesC.size()) {
        flux << "(";
        for (auto const & x : s.sboxesC_in) if (!binary_search(s.sboxesC.begin(), s.sboxesC.end(), x)) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
        flux << ")";
      }
      flux << "\\n";
      flux << "sol: " << s.nbSols();
      flux << "\"";
      flux << ",style=filled,fillcolor=\"thistle1\",shape=\"rectangle\"]" << endl;
      flux << " lbl" << s.id() << endl;
    }
    else {
      if (s.node1 == nullptr){return flux;}
      auto s1 = *s.node1;
      auto s2 = *s.node2;
      flux << "node [label=\"";
      flux << "sol: N "; if (s.nbSols() >= c.getNpairs()) flux << "+ ";
      flux << s.nbSols() - c.getNpairs() << "\\ntime: N + " << s.timeON() - c.getNpairs() << "\"";
      flux << ",style=filled,fillcolor=\"paleturquoise1\"";
      if (s1.nbSols() <= s.nbSols() + 0.001 || s2.nbSols() <= s.nbSols() + 0.001) flux << ",shape=\"ellipse\"";
      else flux << ",shape=\"rectangle\"";
      flux << "]" << endl;
      flux << " lbl" << s.id() << endl;

      if (s2.dependOnPC() || s1.nbSols() + 0.01 < s.nbSols()) {
        if (s1.nbVars() > 0) {
          flux << s1;
          if (my_set.count(make_pair(s1.id(), s.id())) == 0) {
            flux << "lbl" << s1.id() << " -> " << "lbl" << s.id() << endl;
            my_set.emplace(s1.id(), s.id());
          }
        }
        if (s2.nbVars() > 0) {
          flux << s2;
          if (my_set.count(make_pair(s2.id(), s.id())) == 0) {
            flux << "lbl" << s2.id() << " -> " << "lbl" << s.id() << endl;
            my_set.emplace(s2.id(), s.id());
          }
        }
      }
      else {
        vector<Solver> v (1, s2);
        Solver ss = s2;
        while (s1.node1 != nullptr && !s1.node2->dependOnPC() && s1.node1->nbSols() + 0.001 >= s1.nbSols() && s1.node2->nbStateVars() <= 1) {
          v.emplace_back(*s1.node2);
          ss = merge(ss, *s1.node2);
          s1 = *s1.node1;
        }
        if (s1.nbVars() > 0) {
          flux << s1;
          if (my_set.count(make_pair(s1.id(), s.id())) == 0) {
            flux << "lbl" << s1.id() << " -> " << "lbl" << s.id() << endl;
            my_set.emplace(s1.id(), s.id());
          }
        }
        flux << "node [label=\"";
        unsigned cpt = 0;
        unsigned x = (v.size() >= 3) ? v.size()/2 : v.size()+1;
        for (auto rit = v.rbegin(); rit != v.rend(); ++rit) {
          if (cpt == x) flux << "\\n ";
          if (rit != v.rbegin()) flux << " -> ";
          for (auto x : rit->sboxesP) {
            flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
            ++cpt;
          }
          if (rit->sboxesP_in.size() > rit->sboxesP.size()) {
            flux << "(";
            bool flag_space = false;
            for (auto const & x : rit->sboxesP_in) if (!binary_search(rit->sboxesP.begin(), rit->sboxesP.end(), x)) {
              if (flag_space) flux << " ";
              else flag_space = true;
              flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "]";
              ++cpt;
            }
            flux << ")";
          }

          for (auto x : rit->sboxesC) {
            flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
            ++cpt;
          }
          if (rit->sboxesC_in.size() > rit->sboxesC.size()) {
            flux << "(";
            bool flag_space = false;
            for (auto const & x : rit->sboxesC_in) if (!binary_search(rit->sboxesC.begin(), rit->sboxesC.end(), x)) {
              if (flag_space) flux << " ";
              else flag_space = true;
              flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "]";
              ++cpt;
            }
            flux << ")";
          }
        }
        flux << "\\n";
        flux << "sol: " << ss.nbSols();
        flux << "\"";
        flux << ",style=filled,fillcolor=\"thistle1\",shape=\"rectangle\"]" << endl;
        flux << " lbl" << ss.id() << endl;
        if (my_set.count(make_pair(ss.id(), s.id())) == 0) {
          flux << "lbl" << ss.id() << " -> " << "lbl" << s.id() << endl;
          my_set.emplace(ss.id(), s.id());
        }
      }
    }
    return flux;
}

Solver findCommon(vector<std::shared_ptr<Solver>> & v) {
  bool found = true;
  for (unsigned i = 1; i < v.size(); ++i) {
    if (v[i-1]->sboxesP != v[i]->sboxesP) found = false;
    else if (v[i-1]->sboxesC != v[i]->sboxesC) found = false;
    else if (v[i-1]->sboxesP_in != v[i]->sboxesP_in) found = false;
    else if (v[i-1]->sboxesC_in != v[i]->sboxesC_in) found = false;
    if (!found) break;
  }
  if (found) return *v[0];

  unsigned ind = 0;
  for (unsigned i = 1; i < v.size(); ++i) if (v[i]->nbVars() > v[ind]->nbVars()) ind = i;
  auto s = v[ind];
  v[ind] = move(v.back());
  v.pop_back();
  v.emplace_back(s->node1);
  if (s->node2->PC) v.emplace_back(s->node2);
  return findCommon(v);
}

Solver refine(Solver const & s) {
  if (s.node1 == nullptr || s.node2 == nullptr) return s;
  auto const & s1 = *s.node1;
  auto const & s2 = *s.node2;
  if (!s1.dependOnPC() && s2.dependOnPC()) return refine(merge(s2,s1));
  if (s1.dependOnPC() == s.dependOnPC() && s.nbVars() == s1.nbVars()) return refine(s1);
  if (s2.dependOnPC() == s.dependOnPC() && s.nbVars() == s2.nbVars()) return refine(s2);
  if (s1.dependOnPC() && !s2.dependOnPC() && (s2.nbStateVars() > 1 || s2.nbVars() > 1 + 2*s2.nbStateVars())) {
    auto const & s21 = *s.node2->node1;
    auto const & s22 = *s.node2->node2;
    auto ss1 = merge(s1,s21);
    auto ss2 = merge(s1,s22);
    if (ss1.timeON() <= s.timeON() + 0.01 && ss1.nbSols() + 0.001 < s1.nbSols() + s21.nbSols()) {
      auto sf = merge(ss1, s22);
      if (sf.timeON() <= s.timeON() + 0.01) return refine(sf);
    }
    if (ss2.timeON() <= s.timeON() + 0.01 && ss2.nbSols() + 0.001 < s1.nbSols() + s22.nbSols()) {
      auto sf = merge(ss2, s21);
      if (sf.timeON() <= s.timeON() + 0.01) return refine(sf);
    }
    return merge(refine(s1),s2);
  }
  return merge(refine(s1),refine(s2));
}

void printSolverInFile(const char *filename, Solver mySolver){
    fstream file;
    file.open(filename, ios::out);

    if (!file){
        cout<<"Error while creating the file";
    }
    else{
        file << "digraph mygraph {" << endl;
        file << "node [fontname=\"Helvetica,Arial,sans-serif\"]" << endl;
        file << "edge [fontname=\"Helvetica,Arial,sans-serif\"]" << endl;
        file << "node [shape=box]" << endl;

        file << mySolver;

        file << "node [label=\"";
        file << "memory: " << mySolver.mem() << "\\n";
        file << "precomputation: " << mySolver.timeOFF();
        file << "\",shape=record, color=black, fillcolor=white, fontcolor=black, style=solid]" << endl;
        file << " lbl111111111" << endl;
        file << "}";
        cout << "File created successfully" << endl;
        file.close();
    }
}
