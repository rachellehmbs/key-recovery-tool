#include <functional>
#include "Solver.hpp"

using namespace std;

Solver::Solver() : PC (true), time_on (cipher.getNpairs()), time_off (0.), memory (0.), nbsols (time_on), node1 (nullptr), node2 (nullptr) {
  // unsigned const & nbbitssbox = cipher.getLenSB();
  // unsigned const & nbbits = cipher.getSizeBlock();
  // unsigned const & nbsboxes = nbbits/nbbitssbox;
  // for (unsigned x = 0; x < nbsboxes; ++x) {
  //   if (cipher.activitySB(x) != 0) target.emplace_back(x);
  //   if (cipher.activitySB((cipher.getNrR()-1)*nbsboxes + x) != 0) target.emplace_back((cipher.getNrR()-1)*nbsboxes + x);
  // }
  // target_all = target;

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
        // target = Solver::getCipher().getRelatedSboxes(sb);
        // sort(target.begin(), target.end());
        // target_all = target;
        // cout << sb << ": ";
        // for (auto x : target) cout << x << " ";
        // cout << endl;
    }
    else {
        //keys.emplace_back(sb);
        //time_off = 1 - Solver::cipher.matrixKS().computeRank(keys, true); //0 si bit de clé connu, 1 sinon
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

    /*cout << "keys : ";
    for (int i = 0; i < keys.size(); i++)
        cout << keys[i] << " ";
    cout << endl;*/

    cout << "nr sols : " << nbsols << endl;
    cout << "time online : " << time_on << endl;
    cout << "time offline : "<< time_off << endl;
    cout << "memory : " << memory << endl;
    cout << "is PC : "<< PC << endl;

    cout << endl;

    //if (node1 != nullptr) node1->printSolver();
    //if (node2 != nullptr) node2->printSolver();
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
                  //getchar();
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
                  //if (binary_search(keys.begin(), keys.end(), b+l + (r+1)*nbbits)) nbsols -= 1; //ok
                  if (flag_full_sbox) {
                    //extrakey.emplace_back(b+l + (r+1)*nbbits);
                    mykey.emplace_back(cipher.getPERM()[b+l] + (r+1)*nbbits);
                  }

              }
          }
          else {
              auto j = (r+1)*nbsboxes + cipher.getPERM()[b+l] / nbbitssbox; //ok //j takes as value the index of the SB which influenced the l^th bit of the SB
              if (binary_search(sboxesC.begin(), sboxesC.end(), j)) { //in other words, if the lth bit of the SB has already been guessed/fixed, ie the value of the pair on this bit is guessed/fixed
                  //if (binary_search(keys.begin(), keys.end(), cipher.getPERMinv()[b+l] + (r+1)*nbbits)) nbsols -= 1; //ok
                  if (flag_full_sbox) {
                    //extrakey.emplace_back(b+l + (r+1)*nbbits);
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
    //for (auto s : sboxesP_in) nbsols += cipher.getLenSB() - cipher.getFilter(s);
    //for (auto s : sboxesC_in) nbsols += cipher.getLenSB() - cipher.getFilter(s);
    for (auto s : sboxesP_in) nbsols += cipher.nbSolsIn(s);
    for (auto s : sboxesC_in) nbsols += cipher.nbSolsIn(s);
    if (PC) { //If we're considering at least a solver that solves w/ a number of pairs
        nbsols += cipher.getNpairs();
    }

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
                    //if (binary_search(keys.begin(), keys.end(), k+l)) nbsols -= 1; //key bit is known
                                                                                               // if both are true then there are 2^2 pairs of values possible on this bit
                }
            }
            else {
                auto j = (r-1)*nbsboxes + cipher.getPERMinv()[b+l] / nbbitssbox; //ok //j takes as value the index of the SB which influenced the l^th bit of the SB
                                                                                 //cout << j << endl;
                if (binary_search(sboxesP.begin(), sboxesP.end(), j)) { //in other words, if the lth bit of the SB has already been guessed/fixed, ie the value of the pair on this bit is guessed/fixed
                    if (cipher.activityBitBeforeSB(k + l) == 2) nbsols -= 1; //diff on the bit is not fixed before the SB
                    //if (binary_search(keys.begin(), keys.end(), k+l)) nbsols -= 1; //key bit is known
                    if (cipher.isKnownKeyBit(k+l)) nbsols -= 1;
                    else if (flag_full_sbox) {
                      nbsols -= 1;
                      mykey.emplace_back(k+l);
                    }

                }
                    //getchar();
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
                    //if (binary_search(keys.begin(), keys.end(), b+l + (r+1)*nbbits)) nbsols -= 1; //ok
                    if (cipher.isKnownKeyBit(cipher.getPERM()[b+l] + (r+1)*nbbits)) nbsols -= 1;
                    else if (flag_full_sbox) {
                      nbsols -= 1;
                      mykey.emplace_back(cipher.getPERM()[b+l] + (r+1)*nbbits);
                    }


                }
            }
            else {
                auto j = (r+1)*nbsboxes + cipher.getPERM()[b+l] / nbbitssbox; //ok //j takes as value the index of the SB which influenced the l^th bit of the SB
                if (binary_search(sboxesC.begin(), sboxesC.end(), j)) { //in other words, if the lth bit of the SB has already been guessed/fixed, ie the value of the pair on this bit is guessed/fixed
                    if (cipher.activityBitAfterSB(r*nbbits + b+l) == 2) nbsols -= 1;
                    //if (binary_search(keys.begin(), keys.end(), cipher.getPERMinv()[b+l] + (r+1)*nbbits)) nbsols -= 1; //ok
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

// double nbSolsInt(Solver const & s1, Solver const & s2) {
//   auto int_sboxesP = vector<unsigned> (s1.sboxesP.size() + s2.sboxesP.size());
//   {
//       auto it = set_intersection(s1.sboxesP.begin(), s1.sboxesP.end(), s2.sboxesP.begin(), s2.sboxesP.end(), int_sboxesP.begin());
//       int_sboxesP.resize(it - int_sboxesP.begin());
//   }
//
//   auto int_sboxesC = vector<unsigned> (s1.sboxesC.size() + s2.sboxesC.size());
//   {
//       auto it = set_intersection(s1.sboxesC.begin(), s1.sboxesC.end(), s2.sboxesC.begin(), s2.sboxesC.end(), int_sboxesC.begin());
//       int_sboxesC.resize(it - int_sboxesC.begin());
//   }
//
//   // auto int_keys = vector<unsigned> (s1.keys.size() + s2.keys.size());
//   // {
//   //     auto it = set_intersection(s1.keys.begin(), s1.keys.end(), s2.keys.begin(), s2.keys.end(), int_keys.begin());
//   //     int_keys.resize(it - int_keys.begin());
//   // }
//
//   return computeNbsol(int_sboxesP, int_sboxesC, s1.PC && s2.PC, Solver::cipher);
// }

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
    // res.keys = vector<unsigned> (s1.keys.size() + s2.keys.size());
    // it = set_union (s1.keys.begin(), s1.keys.end(), s2.keys.begin(), s2.keys.end(), res.keys.begin());
    // res.keys.resize(it - res.keys.begin());

    res.PC = (s1.PC || s2.PC);

    res.nbsols = computeNbsol(res.sboxesP, res.sboxesC, res.sboxesP_in, res.sboxesC_in, res.PC, cipher);

    if (!s1.PC && !s2.PC) { //not in the attack yet (we're necessarily merging a sb and its key bits??????????????????????????????????)
        res.time_on = 0.0; //no online time
        res.time_off = max(max(s1.time_off, s2.time_off), res.nbsols); // RQ Rach : pour moi c pas ça le time offline mais je suis pas sure de comprendre : PC c'est forcément un sb mergée avec des key bits ? dans ce cas là je comprends pas que ce soit le max mais à voir ????????????????????????
        res.memory = max(s1.memory, max(s2.memory, min(s1.nbsols, s2.nbsols))); //RQ Rach : voir si ça ok pour moi
    }
    else {
        if (s1.PC) {
            if (s2.PC) {
                res.time_on = max(res.nbsols, max(s1.time_on, s2.time_on)); //ok
                res.time_off = max(s1.time_off, s2.time_off); //Rach: meme probleme qu'au dessus a priori (pas reflechi lgtps)
                res.memory = max(s1.memory, max(s2.memory, min(s1.nbsols, s2.nbsols))); //Rach: à voir là tout de suite je comprends pas le min
            }
            else {
                res.time_on = max(res.nbsols, s1.time_on); //ok pas bsn du else pour celui là si s2 pas PC il est à 0 donc s1.time_on necessairement plus grand, à déplacer
                res.time_off = max(s1.time_off, s2.time_off); //Rach: meme probleme qu'au dessus a priori (pas reflechi lgtps) + pas besoin du else non plus, à déplacer
                res.memory = max(s1.memory, max(s2.memory, s2.nbsols)); //à voir, et du coup à voir si il faut pas fusionner ie le else le truc du dessous sont ils utiles
            }
        }
        else {
            res.time_on = max(res.nbsols, s2.time_on); //ok pas bsn du else pour celui là si s2 pas PC il est à 0 donc s1.time_on necessairement plus grand, à déplacer
            res.time_off = max(s1.time_off, s2.time_off); //Rach: meme probleme qu'au dessus a priori (pas reflechi lgtps) + pas besoin du else non plus, à déplacer
            res.memory = max(s1.memory, max(s2.memory, s1.nbsols));  //à voir, et du coup à voir si il faut pas fusionner ie le else le truc du dessous sont ils utiles
        }
    }

    res.node1 = make_shared<Solver>(s1);
    res.node2 = make_shared<Solver>(s2);

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
    //if (!includes(s1.keys.begin(), s1.keys.end(), s2.keys.begin(), s2.keys.end())) return false;
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
    //if (!includes(s1.keys.begin(), s1.keys.end(), s2.keys.begin(), s2.keys.end())) return false;
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
    //if (s1.time_off > s2.time_off + 0.001) return false;
    //if (!includes(s1.keys.begin(), s1.keys.end(), s2.keys.begin(), s2.keys.end())) return false;
    if (!includes(s1.sboxesP.begin(), s1.sboxesP.end(), s2.sboxesP.begin(), s2.sboxesP.end())) return false;
    if (!includes(s1.sboxesC.begin(), s1.sboxesC.end(), s2.sboxesC.begin(), s2.sboxesC.end())) return false;
    if (!includes(s1.sboxesP_in.begin(), s1.sboxesP_in.end(), s2.sboxesP_in.begin(), s2.sboxesP_in.end())) return false;
    if (!includes(s1.sboxesC_in.begin(), s1.sboxesC_in.end(), s2.sboxesC_in.begin(), s2.sboxesC_in.end())) return false;
    return true;
}

bool isFaster(Solver const & s1, Solver const & s2) {
    //if (s1.PC != s2.PC) return s1.PC == true;
    if (s1.time_on != s2.time_on) return s1.time_on < s2.time_on;
    if (s1.nbsols != s2.nbsols) return s1.nbsols < s2.nbsols;
    auto const & u1 = s1.sboxesP.size() + s1.sboxesC.size();
    auto const & u2 = s2.sboxesP.size() + s2.sboxesC.size();
    if (u1 != u2) return u1 > u2;
    auto const & v1 = s1.sboxesP_in.size() + s1.sboxesC_in.size();
    auto const & v2 = s2.sboxesP_in.size() + s2.sboxesC_in.size();
    if (v1 != v2) return v1 > v2;
    if (s1.memory != s2.memory) return s1.memory < s2.memory;
    if (s1.time_off != s2.time_off) return s1.time_off < s2.time_off;
    return false;
}

/*ostream & operator<<(ostream & flux, Solver const & s) { //overload print
 auto & c = Solver::getCipher();

 unsigned const & nbbitssbox = c.getLenSB();
 unsigned const & nbbits = c.getSizeBlock();
 unsigned const & nbsboxes = nbbits/nbbitssbox;

 if (s.node1 == nullptr) {
 flux << "Le solver n'a pas de noeud 1. On affiche ses SB/key." << endl;
 if (s.sboxesP.empty() && s.sboxesC.empty() && s.keys.empty()) return flux;
 flux << "guess: ";
 for (auto x : s.sboxesP) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s.sboxesC) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s.keys) flux << "k" << x/nbbits << "[" << x%nbbits << "] ";
 flux << " | sol: N + " << s.nbSols() - (s.PC ? c.getNpairs() : 0) << ", time: N + " << s.timeON() - (s.PC ? c.getNpairs() : 0) << endl;
 return flux;
 }

 auto const & s1 = *s.node1;
 auto const & s2 = *s.node2;

 auto const & u1 = s1.sboxesP.size() + s1.sboxesC.size();
 auto const & u2 = s2.sboxesP.size() + s2.sboxesC.size();
 if (s1.PC && (!s2.PC || u2 <= 1)) {
 flux << " ------------------- " << endl;
 flux << " - Noeud 1 :";
 flux << s1 << endl;
 flux << (u1 == 0 ? "guess: " : "match1 with: ");
 for (auto x : s2.sboxesP) if (!binary_search(s1.sboxesP.begin(), s1.sboxesP.end(), x)) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s2.sboxesC) if (!binary_search(s1.sboxesC.begin(), s1.sboxesC.end(), x)) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s2.keys) {
 if (!binary_search(s1.keys.begin(), s1.keys.end(), x) && c.matrixKS().computeRank(vector<unsigned> ({x}), true) == 0) flux << "k" << x/nbbits << "[" << x%nbbits << "] ";
 }
 flux << " | sol: N + " << s.nbSols() - c.getNpairs() << ", time: N + " << s.timeON() - (s.PC ? c.getNpairs() : 0) << endl;
 }
 else {
 if (s2.PC && (!s1.PC || u1 <= 1)) {
 flux << s2 << endl;
 flux << (u2 == 0 ? "guess: " : "match2 with: ");
 for (auto x : s1.sboxesP) if (!binary_search(s2.sboxesP.begin(), s2.sboxesP.end(), x)) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s1.sboxesC) if (!binary_search(s2.sboxesC.begin(), s2.sboxesC.end(), x)) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s1.keys) {
 if (!binary_search(s2.keys.begin(), s2.keys.end(), x) && c.matrixKS().computeRank(vector<unsigned> ({x}), true) == 0) flux << "k" << x/nbbits << "[" << x%nbbits << "] ";
 }
 flux << " | sol: N + " << s.nbSols() - c.getNpairs() << ", time: N + " << s.timeON() - (s.PC ? c.getNpairs() : 0) << endl;
 }
 else {
 flux << " ------------------- " << endl;
 flux << " - N1 :";
 for (auto x : s1.sboxesP) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s1.sboxesC) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s1.keys) flux << "k" << x/nbbits << "[" << x%nbbits << "] ";
 flux << " | sol: N + " << s1.nbSols() - (s1.PC ? c.getNpairs() : 0) << ", time: N + " << s1.timeON() - (s1.PC ? c.getNpairs() : 0) << endl;
 flux << " - N2 :";
 for (auto x : s2.sboxesP) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s2.sboxesC) flux << "SB" << x/nbsboxes << "[" << x%nbsboxes << "] ";
 for (auto x : s2.keys) flux << "k" << x/nbbits << "[" << x%nbbits << "] ";
 flux << " | sol: N + " << s2.nbSols() - (s2.PC ? c.getNpairs() : 0) << ", time: N + " << s2.timeON() - (s2.PC ? c.getNpairs() : 0) << endl;
 flux << " ------------------- N1 : " << endl;
 flux << s1 << endl;
 flux << " ------------------- N2 : " << endl;
 flux << s2 << endl;
 flux << " ------------------- " << endl;
 }
 }

 return flux;
 }*/

#if 0
size_t Solver::id() const {
    hash<unsigned> h_u;
    hash<double> h_d;
    size_t res = 0;
    for (auto const & x : sboxesP) res ^= h_u(x ^ 2138310024u);
    for (auto const & x : sboxesC) res ^= h_u(x ^ 1815747931u);
    //for (auto const & x : keys) res ^= h_u(x ^ 209069059u);
    res ^= h_u(PC ^ 940029049u);
    res ^= h_d(time_on + 100.5);
    res ^= h_d(time_off + 200.5);
    res ^= h_d(memory + 300.5);
    res ^= h_d(nbsols + 400.5);
    return res;
}
#else

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
#endif

ostream & operator<<(ostream & flux, Solver const & s) {
    auto & c = Solver::getCipher();
    unsigned const & nbbitssbox = c.getLenSB();
    unsigned const & nbbits = c.getSizeBlock();
    unsigned const & nbsboxes = nbbits/nbbitssbox;

    flux << setprecision(2) << fixed;
        //if (s.sboxesP.empty() && s.sboxesC.empty() && s.keys.empty()) return flux;
    int line_return = 0;
    bool isround = 0;

    flux << "node [label=\"";
        //flux << "lbl" << s.id;


        //if (s.sboxesP.empty() && s.sboxesC.empty() && s.keys.empty()) return flux;
    /*int line_return = 0;
     flux << "lbl" << s.id() << "[label=\"";*/

    if (s.PC == 0){
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
        flux << "\\n ";
        // if (!s.keys.empty()) {
        //     unsigned rk = s.keys[0]/nbbits;
        //     flux << "K" << s.keys[0]/nbbits << " : " ;
        //     for (auto x : s.keys) {
        //         if (x/nbbits != rk) {
        //           flux << "\\n ";
        //           rk = x/nbbits;
        //           flux << "K" << rk << " : " ;
        //           line_return = 0;
        //         }
        //         flux << x%nbbits << " ";
        //         line_return++;
        //         if (line_return%10 == 0)
        //             flux << "\\n ";
        //     }
        //     flux << "\\n ";
        // }
    }

    if (s.PC) {
      flux << " sol: N "; if (s.nbSols() >= c.getNpairs()) flux << "+ ";
      flux << s.nbSols() - c.getNpairs() << "\\n time: N + " << s.timeON() - c.getNpairs() << "\"";
    }
    else {
      flux << " sol: ";
      flux << s.nbSols() << "\\n time: " << s.timeOFF() << "\"";
    }


    if (!s.PC)
        flux << ",style=filled,fillcolor=\"thistle1\",shape=\"rectangle\"]" << endl;
    else {
        flux << ",style=filled,fillcolor=\"paleturquoise1\"";
        if (s.node1 != nullptr){
            auto const & s1 = *s.node1;
            if (s1.PC){
                if (s1.nbSols() > s.nbSols())
                    isround = 1;
            }
        }
        if (!isround){
            if (s.node2 != nullptr){
                auto const & s2 = *s.node2;
                if (s2.PC){
                    if (s2.nbSols() > s.nbSols())
                        isround = 1;
                }
            }
        }
        if (isround)
            flux << ",shape=\"ellipse\"";
        else
            flux << ",shape=\"rectangle\"";
        flux << "]" << endl;
    }
    flux << " lbl" << s.id() << endl;


    /*flux << " sol: N + " << s.nbSols() - (s.PC ? c.getNpairs() : 0) << ", time: N + " << s.timeON() - (s.PC ? c.getNpairs() : 0);
     flux << "\"]" << endl;*/



    if (s.node1 == nullptr){return flux;}
    auto const & s1 = *s.node1;
    auto const & s2 = *s.node2;


    if (s.PC){
        if (s1.nbVars() > 0) {
          flux << s1;
          flux << "lbl" << s1.id() << " -> " << "lbl" << s.id() << endl;
        }
        if (s2.nbVars() > 0) {
          flux << s2;
          flux << "lbl" << s2.id() << " -> " << "lbl" << s.id() << endl;
        }
    }
    return flux;
}


    // void Solver::idSolver(int *ct){
    //     (*ct)++;
    //     id = (*ct);
    //
    //     if (node1 != nullptr) {
    //         auto & s1 = *node1;
    //         s1.idSolver(ct);
    //     }
    //     if (node2 != nullptr) {
    //         auto & s2 = *node2;
    //         s2.idSolver(ct);
    //     }
    // }


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

            //int ct_tree = 0;
            //mySolver.idSolver(&ct_tree);
        file << mySolver;

        file << "}";
        cout << "File created successfully" << endl;
        file.close();
    }
}
