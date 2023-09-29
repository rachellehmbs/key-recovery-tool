#include <map>
#include <set>
//#include <execution>
#include "Search.hpp"
using namespace std;

#if 0
vector<Solver> generateBaseAndKeySolversSpecial(Cipher c) {
    Solver::setCipher(c);
    unsigned const & nbbitssbox = c.getLenSB();
    unsigned const & nbbits = c.getSizeBlock();
    unsigned const & nbsboxes = nbbits/nbbitssbox;
    vector<Solver> res;
    cout << "**** Step 2 : The program creates the basic solvers : (at this point none have PC true). If you press 1, the program prints the resulting basic solvers for each SB." << endl;

    int print = getchar();

    Solver pc;

    //Plaintext side
    int ct = 0;
    for (unsigned r = 0; r < c.getNrSBp(); ++r) {
        for (unsigned i = 0; i < nbsboxes; ++i) { //for each SB on the plaintext side
            if (c.activitySB(r*nbsboxes + i) == 0) continue; //if SB active
            if(print == 49) cout << "SB : (" << r << "," << i << ")" << endl;

            //Init solver for the SB
            Solver s (r*nbsboxes + i, true, false);
            //auto t = s.targetSb();


            //Init a vector solver for the key bit of the SB
            vector<Solver> tmp;
            unsigned forced = 0;
            for (unsigned j = 0; j < nbbitssbox; ++j) {
                Solver ss (nbbitssbox*(r*nbsboxes + i) + j, true, true);
                if (ss.nbSols() == 0.) forced |= 1u << j; //forced at the ends of the end of this loop is binary with 1 where the bits are known
                tmp.emplace_back(std::move(ss)); //tmp[i] is the ith bit of the sb, has time_off = nb_sol = 0 if bit known, 1 otherwise
            }

            //Next loop starts at "111111..1" (length of the SB) if first round, else starts at 0, and runs 2^(nr bits unknown) times
            for (unsigned k = (r == 0) ? (1u << nbbitssbox) - 1 : 0; k < (1u << nbbitssbox); ++k) {
                if ((k & forced) != forced) continue; //runs only if k has 1s at least where forced does ie where the bits that are known
                //typically, if forced = 000000 (notably in the case of the first round) then k starts at 111111 and k&forced = forced so it runs once with k = 111111
                //else, if not the first round, supposed that all 6 bits are known ie forced is equal to 111111 so it runs only with k = 111111, but it is saved that these bits are known
                //if the first 4 bits are known forced is equal to 111100 then it runs with
                //k = 111100
                //k = 111101
                //k = 111110
                //k = 111111

                auto ss = s;

                //Create the SB base solver by adding all unknown key bits to the solver
                //we read k and for each bit of k that is 1, suppose the ith bit is 1, we merge the base solver of the SB (saved in ss) with the ith solver
                //all bits of the first/last round are merged, known and unknown
                //for the other rounds:
                    //the bits that are known are always merged (k always has 1 where the bits are known)
                    //as for the unknown bits, all cases are considered

                for (unsigned b = 0; b < nbbitssbox; ++b) if (((k >> b) & 1) != 0) ss = merge(ss, tmp[b]); //where bits are known, we merge

                //ss.setTargetSb(t);

                // if (r == 0) {
                //   auto sss = merge(ss, pc);
                //   if (sss.nbSols() <= pc.nbSols()) ss = move(sss);
                // }


                //if (r == 0 && !ss.dependOnPC()) cout << "weird 1" << endl;
                //if (r != 0 && ss.dependOnPC()) cout << "weird 2" << endl;

                //The resulting base solver for the SB is saved in res
                //RQ : typiquement le cas plus haut pour une SB où 4 bits sont connus et 2 pas alors on va avoir un res.emplace_back 4 = 2^2 fois

                res.emplace_back(std::move(ss));
                if(print == 49){
                    cout << res.back();
                    getchar();
                }
            }
        }
    }


    //Ciphertext side
    for (unsigned r = c.getNrR() - c.getNrSBc(); r < c.getNrR(); ++r) {
        for (unsigned i = 0; i < nbsboxes; ++i) {
            if (c.activitySB(r*nbsboxes + i) == 0) continue;
            if(print == 49) cout << "SB : (" << r << "," << i << "), ";
            Solver s (r*nbsboxes + i, false, false);
            auto t = s.targetSb();

            vector<Solver> tmp;
            unsigned forced = 0;
            for (unsigned j = 0; j < nbbitssbox; ++j) {
                Solver ss;
                if (r == c.getNrR() - 1){
                    //Solver ss (nbbitssbox*(r+1)*nbsboxes + i*nbbitssbox+j, true, true); //no linear layer on the last round
                    Solver ss (nbbitssbox*(r+1)*nbsboxes + c.getPERM()[i*nbbitssbox+j], true, true);
                    if (ss.nbSols() == 0.) forced |= 1u << j;
                    tmp.emplace_back(std::move(ss));
                }
                else{
                    Solver ss (nbbitssbox*(r+1)*nbsboxes + c.getPERM()[i*nbbitssbox+j], true, true);
                    if (ss.nbSols() == 0.) forced |= 1u << j;
                    tmp.emplace_back(std::move(ss));
                }
            }
            for (unsigned k = (r == c.getNrR() - 1) ? (1u << nbbitssbox) - 1 : 0; k < (1u << nbbitssbox); ++k) {
                //il n'y a pas le if ((k & forced) != forced) continue; ici?
                if ((k & forced) != forced) continue;
                auto ss = s;
                for (unsigned b = 0; b < nbbitssbox; ++b) if (((k >> b) & 1) != 0) ss = merge(ss, tmp[b]);

                ss.setTargetSb(t);

                // if (r == c.getNrR() - 1) {
                //   auto sss = merge(ss, pc);
                //   if (sss.nbSols() <= pc.nbSols()) ss = move(sss);
                // }

                res.emplace_back(std::move(ss));
                if(print == 49){
                    cout << endl << res.back();
                    getchar();
                }
            }
        }
    }

    cout << "The basic solvers have been created, printed if you pressed 1, and put in res." << endl;
    cout << endl << "Number of basic solvers put in the vector res :  " << res.size() << endl;

    getchar();

    return res;
}

#else
vector<Solver> generateBaseAndKeySolversSpecial(Cipher c) {
    Solver::setCipher(c);
    unsigned const & nbbitssbox = c.getLenSB();
    unsigned const & nbbits = c.getSizeBlock();
    unsigned const & nbsboxes = nbbits/nbbitssbox;
    vector<Solver> res;
    cout << "**** Step 2 : The program creates the basic solvers : (at this point none have PC true). If you press 1, the program prints the resulting basic solvers for each SB." << endl;

    int print = getchar();

    //Plaintext side
    for (unsigned r = 0; r < c.getNrSBp(); ++r) {
        for (unsigned i = 0; i < nbsboxes; ++i) { //for each SB on the plaintext side
            if (c.activitySB(r*nbsboxes + i) == 0) continue; //if SB active
            if(print == 49) cout << "SB : (" << r << "," << i << ")" << endl;

            //Init solver for the SB
            Solver s (r*nbsboxes + i, true, false);
            Solver ss (r*nbsboxes + i, true, true);

            res.emplace_back(merge(s,ss));
            if (c.getFilter(r*nbsboxes + i) > 0.001) res.emplace_back(move(ss));
        }
    }

    #if 1

    //Ciphertext side
    for (unsigned r = c.getNrR()-1; r >= c.getNrR() - c.getNrSBc(); --r) {
        for (unsigned i = 0; i < nbsboxes; ++i) {
            if (c.activitySB(r*nbsboxes + i) == 0) continue;
            if(print == 49) cout << "SB : (" << r << "," << i << "), ";
            Solver s (r*nbsboxes + i, false, false);
            Solver ss (r*nbsboxes + i, false, true);

            res.emplace_back(merge(s,ss));
            if (c.getFilter(r*nbsboxes + i) > 0.001) res.emplace_back(move(ss));
        }
    }

    #else

    //Ciphertext side
    for (unsigned r = c.getNrR()-1; r >= c.getNrR()-3; --r) {
        for (unsigned i = 0; i < nbsboxes; ++i) {
            if (c.activitySB(r*nbsboxes + i) == 0) continue;
            if(print == 49) cout << "SB : (" << r << "," << i << "), ";
            Solver s (r*nbsboxes + i, false, false);
            Solver ss (r*nbsboxes + i, false, true);

            if (r >= c.getNrR()-2) {
              res.emplace_back(merge(s,ss));
            }
            if (c.getFilter(r*nbsboxes + i) > 0.001) res.emplace_back(move(ss));

        }
    }



    #endif

    cout << "The basic solvers have been created, printed if you pressed 1, and put in res." << endl;
    cout << endl << "Number of basic solvers put in the vector res :  " << res.size() << endl;

    for (auto const & s : res) s.printSolver();

    return res;
}

#endif
/******************************************************************************* BONNE VERSION SEARCH BEST SOLVER**************************************************************************************/

void addOff(vector<Solver> & done, Solver s_add, double bound_off) {
  if (any_of(done.begin(), done.end(), [&s_add](auto const & ss){return isBetterNoMem(ss,s_add);})) return;
  {
    unsigned i = 0, n = done.size();
    while (i < n) {
      auto & s = done[i];
      if (isBetterNoMem(s_add, s)) s = done[--n];
      else ++i;
    }
    done.resize(n);
  }
  vector<Solver> toprocess;
  toprocess.emplace_back(move(s_add));
  while (!toprocess.empty()) {
    unsigned ind = 0;
    for (unsigned i = 1; i < toprocess.size(); ++i) {
      if (toprocess[i].nbSols() < toprocess[ind].nbSols()) ind = i;
    }
    auto s = move(toprocess[ind]);
    toprocess[ind] = move(toprocess.back());
    toprocess.pop_back();
    vector<Solver> tmp;
    tmp.reserve(done.size());
    for (auto const & s1 : done) {
      auto s2 = merge(s1, s);
      if (s2.nbVars() == s1.nbVars() || s2.nbVars() == s.nbVars()) continue;
      //if (s2.nbVars() != s1.nbVars() + s.nbVars()) continue;
      //if (s2.nbSols() >= s1.nbSols() + s.nbSols() - 0.001) continue;
      if (s2.timeOFF() > bound_off) continue;
      if (any_of(tmp.begin(), tmp.end(), [&s2](auto const & ss){return isBetterNoMem(ss,s2);})) continue;
      if (any_of(done.begin(), done.end(), [&s2](auto const & ss){return isBetterNoMem(ss,s2);})) continue;
      if (any_of(toprocess.begin(), toprocess.end(), [&s2](auto const & ss){return isBetterNoMem(ss,s2);})) continue;
      unsigned i = 0, n = tmp.size();
      while (i < n) {
        if (isBetterNoMem(s2, tmp[i])) tmp[i] = move(tmp[--n]);
        else ++i;
      }
      tmp.resize(n);
      tmp.emplace_back(move(s2));
    }
    done.emplace_back(move(s));
    {
      unsigned i = 0, n = done.size();
      while (i < n) {
        auto & s = done[i];
        if (any_of(tmp.begin(), tmp.end(), [s](auto const & ss){return isBetterNoMem(ss, s);})) s = done[--n];
        else ++i;
      }
      done.resize(n);
    }
    {
      unsigned i = 0, n = toprocess.size();
      while (i < n) {
        auto & s = toprocess[i];
        if (any_of(tmp.begin(), tmp.end(), [s](auto const & ss){return isBetterNoMem(ss, s);})) s = toprocess[--n];
        else ++i;
      }
      toprocess.resize(n);
    }
    for (auto & ss : tmp) toprocess.emplace_back(move(ss));
  }
}

void updateFree(Solver & s, vector<Solver> const & base) {
  for (auto const & ss : base) {
    auto s2 = merge(s, ss);
    if (s2.nbSols() > s.nbSols() + 0.001) continue;
    if (s2.nbVars() == s.nbVars()) continue;
    s = move(s2);
    return updateFree(s, base);
  }
}

#if 0

Solver searchBestSolver(Cipher c) {
    auto toprocess = generateBaseAndKeySolversSpecial(c); //toprocess is a vector of the basic solvers with PC = 0

    //ajout d'un Solver qui resssemble à final à la fin de toprocess
    //toprocess.emplace_back();

    double bound_off = 10.0;
    bool flag_fast_off = true;
    bool flag_fast_on = true;

    unsigned const & nbbitssbox = c.getLenSB();
    unsigned const & nbbits = c.getSizeBlock();
    unsigned const & nbsboxes = nbbits/nbbitssbox;

    Solver final;

    for (auto const & s : toprocess) {
        final = merge(final,s);
    }



    cout << "nbvar: " << final.nbVars() << " " << endl;
    auto nvar = final.nbVars();

    Solver::resizeMat(final.getKeyBits());

    cout << "free filter: ";

    Solver pc; // find free filters
    bool flag = true;
    while (flag) {
      flag = false;
      unsigned i = 0, n = toprocess.size();
      while (i < n) {
        auto s = merge(pc, toprocess[i]);
        if (s.nbSols() <= pc.nbSols()) {
          toprocess[i] = toprocess[--n];
          if (s.nbVars() > pc.nbVars()) pc = move(s);
          flag = true;
          break;
        }
        else ++i;
      }
      toprocess.resize(n);
    }
    cout << 100.0 - pc.nbSols() << endl;

    pc.printSolver();
    auto const & v = pc.getKeyBits();
    for (auto x : v) cout << "k" << x/64 << "[" << x%64 << "] ";
    cout << endl;
    getchar();


    double my_bound;
    { // find heuristic solution
      auto s = pc;
      auto tmp = toprocess;
      while (!tmp.empty()) {
        vector<Solver> tmp2;
        for (auto const & ss : tmp) tmp2.emplace_back(merge(s, ss));
        unsigned ind = 0;
        for (unsigned i = 1; i < tmp2.size(); ++i) {
          if (tmp2[i].timeON() != tmp2[ind].timeON()) {
            if (tmp2[i].timeON() < tmp2[ind].timeON()) ind = i;
          }
          else if (tmp2[i].nbSols() != tmp2[ind].nbSols()) {
            if (tmp2[i].nbSols() < tmp2[ind].nbSols()) ind = i;
          }
          else if (tmp2[i].nbVars() > tmp2[ind].nbVars()) ind = i;
        }
        if (tmp2[ind].nbVars() > s.nbVars()) s = tmp2[ind];
        tmp[ind] = move(tmp.back());
        tmp.pop_back();
      }
      cout << "heuristic solution: " << endl;
      s.printSolver();
      //return s;
      //getchar();
      if (s.timeON() == s.nbSols()) {
        auto const & v = s.getKeyBits();
        for (auto x : v) cout << "k" << x/64 << "[" << x%64 << "] ";
        cout << endl;
        cout << "the solution is optimal" << endl;
        return s;
      }
      my_bound = s.timeON() + 0.001;
    }

    vector<Solver> base_sbox;
    for (auto const & s : toprocess) {
      // if (none_of(toprocess.begin(), toprocess.end(),[&s](auto const & ss){return s.sboxesFromP() == ss.sboxesFromP() && s.sboxesFromC() == ss.sboxesFromC() && s.keyBits().size() > ss.keyBits().size();} )) {
      //   base_wo_key.emplace_back(s);
      // }
      if (s.nbStateVars() == 1) base_sbox.emplace_back(s);
    }
    auto base_all = toprocess;

    toprocess.clear();

    vector<vector<unsigned>> my_relations (base_sbox.size());
    vector<Solver> head_P, head_C;

    vector<Solver> maybe;

    for (unsigned i = 0; i < base_sbox.size(); ++i) {
      auto const & si = base_sbox[i];
      for (unsigned j = 0; j < base_sbox.size(); ++j) {
        auto const & sj = base_sbox[j];
        if (i == j) continue;
        if (si.sboxesFromP().size() != sj.sboxesFromP().size()) continue;
        if (!si.sboxesFromP().empty()) {
          if (si.sboxesFromP()[0] <= sj.sboxesFromP()[0]) continue;
          auto sij = merge(si, sj);
          if (sij.nbSols() < si.nbSols() + sj.nbSols() - 0.001) my_relations[i].emplace_back(j);
        }
        else if (!si.sboxesFromC().empty()) {
          if (si.sboxesFromC()[0] >= sj.sboxesFromC()[0]) continue;
          auto sij = merge(si, sj);
          if (sij.nbSols() < si.nbSols() + sj.nbSols() - 0.001) my_relations[i].emplace_back(j);
        }
      }
    }
    for (unsigned i = 0; i < base_sbox.size(); ++i) {
      auto const & si = base_sbox[i];
      if (my_relations[i].empty()){
        maybe.emplace_back(si);
      }
      else {
        auto sj = base_sbox[my_relations[i][0]];
        for (unsigned j = 1; j < my_relations[i].size(); ++j) sj = merge(sj, base_sbox[my_relations[i][j]]);
        auto sij = merge(sj, si);
        if (sij.nbSols() < sj.nbSols() - 0.001) {
          toprocess.emplace_back(si);
          if (!si.sboxesFromP().empty()) head_P.emplace_back(si);
          else if (!si.sboxesFromC().empty()) head_C.emplace_back(si);
        }
        else {
          /*
          set<unsigned> myset;
          set<unsigned> myset_wait (my_relations[i].begin(), my_relations[i].end());
          while (!myset_wait.empty()) {
            auto x = *myset_wait.begin();
            myset_wait.erase(myset_wait.begin());
            if (myset.count(x) != 0) continue;
            else {
              myset.insert(x);
              myset_wait.insert(my_relations[x].begin(), my_relations[x].end());
            }
          }
          if (!si.sboxesFromP().empty()) {
            auto it = myset.begin();
            sj = base_sbox[*it];
            ++it;
            while (it != myset.end()) {sj = merge(sj, base_sbox[*it]); ++it;}
            toprocess.emplace_back(merge(sj,si));
          }
          else if (!si.sboxesFromC().empty()) {
            auto it = myset.rbegin();
            sj = base_sbox[*it];
            ++it;
            while (it != myset.rend()) {sj = merge(sj, base_sbox[*it]); ++it;}
            toprocess.emplace_back(merge(sj,si));
          }
          */

          toprocess.emplace_back(sij);
        }
      }
    }
    for (auto const & s : maybe) {
      bool flag = false;
      for (auto const & ss : toprocess) {
        auto sss = merge(s,ss);
        if (sss.nbVars() == ss.nbVars()) {flag = true; break;}
      }
      if (!flag) toprocess.emplace_back(s);
    }


    vector<vector<Solver>> related_P (head_P.size()), related_C (head_C.size());
    for (auto const & s : base_sbox) {
      if (!s.sboxesFromP().empty()) {
        for (unsigned i = 0; i < head_P.size(); ++i) {
          auto const & ss = head_P[i];
          if (ss.sboxesFromP()[0] <= s.sboxesFromP()[0]) continue;
          auto sss = merge(ss, s);
          //if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001) related_P[i].emplace_back(s);
          if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001 && sss.timeOFF() <= bound_off) addOff(related_P[i], sss, bound_off);
        }
      }
      else if (!s.sboxesFromC().empty()) {
        for (unsigned i = 0; i < head_C.size(); ++i) {
          auto const & ss = head_C[i];
          if (ss.sboxesFromC()[0] >= s.sboxesFromC()[0]) continue;
          auto sss = merge(ss, s);
          //if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001) related_C[i].emplace_back(s);
          if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001 && sss.timeOFF() <= bound_off) addOff(related_C[i], sss, bound_off);
        }
      }
    }

    for (unsigned i = 0; i < head_P.size(); ++i) {
      cout << head_P[i].sboxesFromP()[0] << ": ";
      for (auto & s : related_P[i]) updateFree(s, base_all);
      for (auto const & s : related_P[i]) {
        cout << "(";
        for (auto x : s.sboxesFromP()) cout << x << " ";
        cout << "- " << s.nbSols();
        cout << ") ";
      }
      cout << endl;
    }
    for (unsigned i = 0; i < head_C.size(); ++i) {
      cout << head_C[i].sboxesFromC()[0] << ": ";
      for (auto & s : related_C[i]) updateFree(s, base_all);
      for (auto const & s : related_C[i]) {
        cout << "(";
        for (auto x : s.sboxesFromC()) cout << x << " ";
        cout << "- " << s.nbSols();
        cout << ") ";
      }
      cout << endl;
    }




    vector<Solver> done;
    for (auto const & s : base_all) if (s.nbStateVars() == 0) toprocess.emplace_back(s);
    for (auto const & s : toprocess) s.printSolver();
    getchar();

    //toprocess = base_all;
    if (flag_fast_off) {
      for (auto const & v : related_P) for (auto const & s : v) toprocess.emplace_back(s);
      for (auto const & v : related_C) for (auto const & s : v) toprocess.emplace_back(s);
    }
    toprocess.emplace_back(pc);

    my_bound = 106;


    for (;;) {
      while (!toprocess.empty()) {
          unsigned ind = 0;
          double maxtime = 0.0;
          for (unsigned i = 1; i < toprocess.size(); ++i) {
              if (isFaster(toprocess[i],toprocess[ind])) ind = i;
              else if (toprocess[i].timeON() > maxtime) maxtime = toprocess[i].timeON();
          }
          auto s = std::move(toprocess[ind]);
          updateFree(s, base_all);
          auto const & best_time = s.timeON();
          if (s.nbStateVars() == final.nbStateVars()) {
            s.printSolver();
            return s;
          }
          cout << "\r" << done.size() << " - " << toprocess.size() << " - " << s.timeON() << " | " << s.nbSols() << " " << maxtime << " " << flush;
          toprocess[ind] = std::move(toprocess.back());
          toprocess.pop_back();
          if (s.sboxesFromP().size() == final.sboxesFromP().size()) s.getDST() |= 3;
          if (s.sboxesFromC().size() == final.sboxesFromC().size()) s.getDST() |= 3;
          // {
          //   unsigned  i = 0, n = done.size();
          //   while (i < n) {
          //     if (isBetter(s,done[i])) done[i] = move(done[--n]);
          //     else ++i;
          //   }
          //   done.resize(n);
          //   i = 0; n = toprocess.size();
          //   while (i < n) {
          //     if (isBetter(s,toprocess[i])) toprocess[i] = move(toprocess[--n]);
          //     else ++i;
          //   }
          //   toprocess.resize(n);
          // }

          vector<Solver> tmp;
          for (auto const & ss : done) {
              if (flag_fast_off && !ss.dependOnPC() && !s.dependOnPC()) continue; //j'autorise merge que si au moins 1 des 2 a PC = 1
              //if (ss.dependOnPC() && s.dependOnPC()) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() != 1 && s.nbStateVars() != 1) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() == 1 && ss.nbSols() > 2*nbbitssbox - 1) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && s.nbStateVars() == 1 && s.nbSols() > 2*nbbitssbox - 1) continue;
              auto sss = merge(ss, s);
              if (sss.nbSols() > my_bound) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && sss.timeOFF() > bound_off) continue;
              if (sss.getDST() == 0) continue;
              if ((sss.nbVars() == ss.nbVars() && sss.dependOnPC() == ss.dependOnPC()) || (sss.nbVars() == s.nbVars() && sss.dependOnPC() == s.dependOnPC())) continue;
              bool flag = false;
              if (sss.nbSols() <= ss.nbSols() + 0.001 && sss.timeON() <= ss.timeON() + 0.001) flag = true;
              else if (sss.nbSols() <= s.nbSols() + 0.001 && sss.timeON() <= s.timeON() + 0.001) flag = true;
              else if (ss.dependOnPC() != s.dependOnPC() && sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              else if ((!ss.dependOnPC() || !s.dependOnPC()) && sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              //flag =  true;
              //else if (!sss.targetSb().empty()) flag = true;
              //else if (sss.nbSols() + nbSolsInt(ss,s) + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              if (flag && none_of(tmp.begin(), tmp.end(), [&sss, best_time](auto const & so){return isBetterNoMem(so, sss);})) {
                //updateFree(sss, base_w_key);
                unsigned i_tmp = 0, n_tmp = tmp.size();
                while (i_tmp < n_tmp) {
                  if (isBetterNoMem(sss, tmp[i_tmp])) tmp[i_tmp] = std::move(tmp[--n_tmp]);
                  else ++i_tmp;
                }
                tmp.resize(n_tmp);
                tmp.emplace_back(std::move(sss));
              }
          }
          //test sur les nouveaux solvers que je veux ajouter à toprocess
          //je vire ceux qui en contiennent d'autres/sont meilleurs que d'autres
          //s.printSolver();
          done.emplace_back(std::move(s));
          /* for (auto const & s1 : done) {
               unsigned i = 0, n = tmp.size();
               while (i < n) {
                   if (isBetter(s1, tmp[i])) tmp[i] = std::move(tmp[--n]);
                   else ++i;
               }
               tmp.resize(n);
           }

          for (auto const & s1 : toprocess) {
              unsigned i = 0, n = tmp.size();
              while (i < n) {
                  if (isBetter(s1, tmp[i])) tmp[i] = std::move(tmp[--n]);
                  else ++i;
              }
              tmp.resize(n);
          }

          for (auto const & s1 : tmp) {
              unsigned i = 0, n = done.size();
              while (i < n) {
                  if (isBetter(s1, done[i])) done[i] = std::move(done[--n]);
                  else ++i;
              }
              done.resize(n);
          }

          for (auto const & s1 : tmp) {
              unsigned i = 0, n = toprocess.size();
              while (i < n) {
                  if (isBetter(s1, toprocess[i])) toprocess[i] = std::move(toprocess[--n]);
                  else ++i;
              }
              toprocess.resize(n);
          }*/
          {
            unsigned i = 0, n = tmp.size();
            while (i < n) {
                auto const & tmpi = tmp[i];
                if (any_of(done.begin(), done.end(), [&tmpi, best_time](auto const & s1) {return isBetterNoMem(s1, tmpi);})) tmp[i] = std::move(tmp[--n]);
                else ++i;
            }
            tmp.resize(n);
          }
          {
            unsigned i = 0, n = tmp.size();
            while (i < n) {
                auto const & tmpi = tmp[i];
                if (any_of(toprocess.begin(), toprocess.end(), [&tmpi, best_time](auto const & s1) {return isBetterNoMem(s1, tmpi);})) tmp[i] = std::move(tmp[--n]);
                else ++i;
            }
            tmp.resize(n);
          }
          {
            unsigned i = 0, n = done.size();
            while (i < n) {
                auto const & donei = done[i];
                if (any_of(tmp.begin(), tmp.end(), [&donei, best_time](auto const & s1) {return isBetterNoMem(s1, donei);})) done[i] = std::move(done[--n]);
                else ++i;
            }
            done.resize(n);
          }
          {
            unsigned i = 0, n = toprocess.size();
            while (i < n) {
                auto const & toprocessi = toprocess[i];
                if (any_of(tmp.begin(), tmp.end(), [&toprocessi, best_time](auto const & s1) {return isBetterNoMem(s1, toprocessi);})) toprocess[i] = std::move(toprocess[--n]);
                else ++i;
            }
            toprocess.resize(n);
          }

          for (auto & s1 : tmp) {
              // cout << "s1 (" << s1.nbSols() << "|" << s1.timeON() << "): "; for (auto x : s1.sboxesFromP()) cout << x << " ";
              // for (auto x : s1.sboxesFromC()) cout << x << " ";
              // cout << " | "; for (auto x : s1.keyBits()) cout << x << " ";
              // cout << endl;
              toprocess.emplace_back(std::move(s1));
          }

          //cout << "to process: " << endl;
          //for (auto const & s1 : toprocess) s1.printSolver();
          // cout << "done: " << endl;
          // for (auto const & s1 : done) s1.printSolver();
          // getchar();

          //if (!tmp.empty()) getchar();
      }
      break;
    }

    cout << "done" << endl;
    cout << "done: " << endl;
    for (auto const & s1 : done) s1.printSolver();
    getchar();
    getchar();

    return pc;
}

#else

Solver searchBestSolver(Cipher c) {
    auto toprocess = generateBaseAndKeySolversSpecial(c); //toprocess is a vector of the basic solvers with PC = 0

    //ajout d'un Solver qui resssemble à final à la fin de toprocess
    //toprocess.emplace_back();

    double bound_off = 10.0;
    bool flag_fast_off = true;
    bool flag_fast_on = true;

    unsigned const & nbbitssbox = c.getLenSB();
    unsigned const & nbbits = c.getSizeBlock();
    unsigned const & nbsboxes = nbbits/nbbitssbox;

    Solver final;

    for (auto const & s : toprocess) {
        final = merge(final,s);
    }



    cout << "nbvar: " << final.nbVars() << " " << endl;
    auto nvar = final.nbVars();

    Solver::resizeMat(final.getKeyBits());

    cout << "free filter: ";

    Solver pc; // find free filters
    bool flag = true;
    while (flag) {
      flag = false;
      unsigned i = 0, n = toprocess.size();
      while (i < n) {
        auto s = merge(pc, toprocess[i]);
        if (s.nbSols() <= pc.nbSols()) {
          toprocess[i] = toprocess[--n];
          if (s.nbVars() > pc.nbVars()) pc = move(s);
          flag = true;
          break;
        }
        else ++i;
      }
      toprocess.resize(n);
    }
    cout << 100.0 - pc.nbSols() << endl;

    pc.printSolver();


    double my_bound;
    { // find heuristic solution
      auto s = pc;
      auto tmp = toprocess;
      while (!tmp.empty()) {
        vector<Solver> tmp2;
        for (auto const & ss : tmp) tmp2.emplace_back(merge(s, ss));
        unsigned ind = 0;
        for (unsigned i = 1; i < tmp2.size(); ++i) {
          if (tmp2[i].timeON() != tmp2[ind].timeON()) {
            if (tmp2[i].timeON() < tmp2[ind].timeON()) ind = i;
          }
          else if (tmp2[i].nbSols() != tmp2[ind].nbSols()) {
            if (tmp2[i].nbSols() < tmp2[ind].nbSols()) ind = i;
          }
          else if (tmp2[i].nbVars() > tmp2[ind].nbVars()) ind = i;
        }
        if (tmp2[ind].nbVars() > s.nbVars()) s = tmp2[ind];
        tmp[ind] = move(tmp.back());
        tmp.pop_back();
      }
      cout << "heuristic solution: " << endl;
      s.printSolver();
      //return s;
      //getchar();
      if (s.timeON() == s.nbSols()) {
        cout << "the solution is optimal" << endl;
        auto const & v = s.getKeyBits();
        for (auto x : v) cout << "k" << x/64 << "[" << x%64 << "] ";
        cout << endl;
        return s;
      }
      my_bound = s.timeON() + 0.001;
    }

    vector<Solver> base_sbox;
    for (auto const & s : toprocess) {
      // if (none_of(toprocess.begin(), toprocess.end(),[&s](auto const & ss){return s.sboxesFromP() == ss.sboxesFromP() && s.sboxesFromC() == ss.sboxesFromC() && s.keyBits().size() > ss.keyBits().size();} )) {
      //   base_wo_key.emplace_back(s);
      // }
      if (s.nbStateVars() == 1) base_sbox.emplace_back(s);
    }
    auto base_all = toprocess;

    toprocess.clear();

    map<unsigned, unsigned> map_related;
    {
      for (unsigned i = 0; i < base_sbox.size(); ++i) {
        auto const & si = base_sbox[i];
        if (!si.sboxesFromP().empty()) map_related[si.sboxesFromP()[0]] = i;
        else if (!si.sboxesFromC().empty()) map_related[si.sboxesFromC()[0]] = i;
      }
    }

    vector<vector<unsigned>> my_relations (base_sbox.size());
    vector<Solver> head_P, head_C;

    for (unsigned i = 0; i < base_sbox.size(); ++i) {
      auto const & si = base_sbox[i];
      for (unsigned j = 0; j < base_sbox.size(); ++j) {
        auto const & sj = base_sbox[j];
        if (i == j) continue;
        if (si.sboxesFromP().size() != sj.sboxesFromP().size()) continue;
        if (!si.sboxesFromP().empty()) {
          if (si.sboxesFromP()[0] <= sj.sboxesFromP()[0]) continue;
          auto sij = merge(si, sj);
          if (sij.nbSols() < si.nbSols() + sj.nbSols() - 0.001) my_relations[i].emplace_back(j);
        }
        else if (!si.sboxesFromC().empty()) {
          if (si.sboxesFromC()[0] >= sj.sboxesFromC()[0]) continue;
          auto sij = merge(si, sj);
          if (sij.nbSols() < si.nbSols() + sj.nbSols() - 0.001) my_relations[i].emplace_back(j);
        }
      }
    }
    for (unsigned i = 0; i < base_sbox.size(); ++i) {
      auto const & si = base_sbox[i];
      if (!my_relations[i].empty()){
        auto sj = base_sbox[my_relations[i][0]];
        for (unsigned j = 1; j < my_relations[i].size(); ++j) sj = merge(sj, base_sbox[my_relations[i][j]]);
        auto sij = merge(sj, si);
        if (sij.nbSols() < sj.nbSols() - 0.001) {
          if (!si.sboxesFromP().empty()) head_P.emplace_back(si);
          else if (!si.sboxesFromC().empty()) head_C.emplace_back(si);
          my_relations[i].clear();
        }
      }
    }


    vector<vector<Solver>> related_P (head_P.size()), related_C (head_C.size());
    for (auto const & s : base_sbox) {
      if (!s.sboxesFromP().empty()) {
        for (unsigned i = 0; i < head_P.size(); ++i) {
          auto const & ss = head_P[i];
          if (ss.sboxesFromP()[0] <= s.sboxesFromP()[0]) continue;
          auto sss = merge(ss, s);
          //if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001) related_P[i].emplace_back(s);
          if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001 && sss.timeOFF() <= bound_off) addOff(related_P[i], sss, bound_off);
        }
      }
      else if (!s.sboxesFromC().empty()) {
        for (unsigned i = 0; i < head_C.size(); ++i) {
          auto const & ss = head_C[i];
          if (ss.sboxesFromC()[0] >= s.sboxesFromC()[0]) continue;
          auto sss = merge(ss, s);
          //if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001) related_C[i].emplace_back(s);
          if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001 && sss.timeOFF() <= bound_off) addOff(related_C[i], sss, bound_off);
        }
      }
    }

    for (unsigned i = 0; i < head_P.size(); ++i) {
      cout << head_P[i].sboxesFromP()[0] << ": ";
      for (auto & s : related_P[i]) updateFree(s, base_all);
      for (auto const & s : related_P[i]) {
        cout << "(";
        for (auto x : s.sboxesFromP()) cout << x << " ";
        cout << "- " << s.nbSols();
        cout << ") ";
      }
      cout << endl;
    }
    for (unsigned i = 0; i < head_C.size(); ++i) {
      cout << head_C[i].sboxesFromC()[0] << ": ";
      for (auto & s : related_C[i]) updateFree(s, base_all);
      for (auto const & s : related_C[i]) {
        cout << "(";
        for (auto x : s.sboxesFromC()) cout << x << " ";
        cout << "- " << s.nbSols();
        cout << ") ";
      }
      cout << endl;
    }




    vector<Solver> done;

    //toprocess = base_all;
    if (flag_fast_off) {
      for (auto const & v : related_P) for (auto const & s : v) toprocess.emplace_back(s);
      for (auto const & v : related_C) for (auto const & s : v) toprocess.emplace_back(s);
    }
    toprocess.emplace_back(pc);

    my_bound = 106;


    for (;;) {
      while (!toprocess.empty()) {
          unsigned ind = 0;
          double maxtime = 0.0;
          for (unsigned i = 1; i < toprocess.size(); ++i) {
              if (isFaster(toprocess[i],toprocess[ind])) ind = i;
              else if (toprocess[i].timeON() > maxtime) maxtime = toprocess[i].timeON();
          }
          auto s = std::move(toprocess[ind]);
          updateFree(s, base_all);
          auto const & best_time = s.timeON();
          if (s.nbStateVars() == final.nbStateVars()) {
            s.printSolver();
            return s;
          }
          cout << "\r" << done.size() << " - " << toprocess.size() << " - " << s.timeON() << " | " << s.nbSols() << " " << maxtime << " " << flush;
          toprocess[ind] = std::move(toprocess.back());
          toprocess.pop_back();
          if (s.sboxesFromP().size() == final.sboxesFromP().size()) s.getDST() |= 3;
          if (s.sboxesFromC().size() == final.sboxesFromC().size()) s.getDST() |= 3;

          vector<Solver> tmp;
          for (auto const & ss : base_all) {
            if (flag_fast_off && !ss.dependOnPC() && !s.dependOnPC()) continue; //j'autorise merge que si au moins 1 des 2 a PC = 1
            //if (ss.dependOnPC() && s.dependOnPC()) continue;
            if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() != 1 && s.nbStateVars() != 1) continue;
            if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() == 1 && ss.nbSols() > 2*nbbitssbox - 1) continue;
            if (!ss.dependOnPC() && !s.dependOnPC() && s.nbStateVars() == 1 && s.nbSols() > 2*nbbitssbox - 1) continue;
            auto sss = merge(ss, s);
            if (sss.nbSols() > my_bound) continue;
            if (!ss.dependOnPC() && !s.dependOnPC() && sss.timeOFF() > bound_off) continue;
            if (sss.getDST() == 0) continue;
            if ((sss.nbVars() == ss.nbVars() && sss.dependOnPC() == ss.dependOnPC()) || (sss.nbVars() == s.nbVars() && sss.dependOnPC() == s.dependOnPC())) continue;
            bool flag = false;
            if (sss.nbSols() <= ss.nbSols() + 0.001 && sss.timeON() <= ss.timeON() + 0.001) flag = true;
            else if (sss.nbSols() <= s.nbSols() + 0.001 && sss.timeON() <= s.timeON() + 0.001) flag = true;
            else if ((!ss.dependOnPC() || !s.dependOnPC()) && sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
            else if (ss.dependOnPC() != s.dependOnPC()) {
              if (sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) {
                flag = true;
                if (!ss.sboxesFromP().empty()) {
                  auto const & v = my_relations[map_related[ss.sboxesFromP()[0]]];
                  for (auto x : v) {
                    if (!binary_search(sss.sboxesFromP().begin(), sss.sboxesFromP().end(), x)) {flag = false; break;}
                  }
                }
                else if (!ss.sboxesFromC().empty()) {
                  auto const & v = my_relations[map_related[ss.sboxesFromC()[0]]];
                  for (auto x : v) {
                    if (!binary_search(sss.sboxesFromC().begin(), sss.sboxesFromC().end(), x)) {flag = false; break;}
                  }
                }
              }
            }


            if (flag && none_of(tmp.begin(), tmp.end(), [&sss, best_time](auto const & so){return isBetter(so, sss);})) {
              //updateFree(sss, base_w_key);
              unsigned i_tmp = 0, n_tmp = tmp.size();
              while (i_tmp < n_tmp) {
                if (isBetter(sss, tmp[i_tmp])) tmp[i_tmp] = std::move(tmp[--n_tmp]);
                else ++i_tmp;
              }
              tmp.resize(n_tmp);
              tmp.emplace_back(std::move(sss));
            }
          }

          for (auto const & ss : done) {
              if (flag_fast_off && !ss.dependOnPC() && !s.dependOnPC()) continue; //j'autorise merge que si au moins 1 des 2 a PC = 1
              //if (ss.dependOnPC() && s.dependOnPC()) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() != 1 && s.nbStateVars() != 1) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() == 1 && ss.nbSols() > 2*nbbitssbox - 1) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && s.nbStateVars() == 1 && s.nbSols() > 2*nbbitssbox - 1) continue;
              auto sss = merge(ss, s);
              if (sss.nbSols() > my_bound) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && sss.timeOFF() > bound_off) continue;
              if (sss.getDST() == 0) continue;
              if ((sss.nbVars() == ss.nbVars() && sss.dependOnPC() == ss.dependOnPC()) || (sss.nbVars() == s.nbVars() && sss.dependOnPC() == s.dependOnPC())) continue;
              bool flag = false;
              if (sss.nbSols() <= ss.nbSols() + 0.001 && sss.timeON() <= ss.timeON() + 0.001) flag = true;
              else if (sss.nbSols() <= s.nbSols() + 0.001 && sss.timeON() <= s.timeON() + 0.001) flag = true;
              //else if (ss.dependOnPC() != s.dependOnPC() && sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              //else if ((!ss.dependOnPC() || !s.dependOnPC()) && sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              //flag =  true;
              //else if (!sss.targetSb().empty()) flag = true;
              //else if (sss.nbSols() + nbSolsInt(ss,s) + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              if (flag && none_of(tmp.begin(), tmp.end(), [&sss, best_time](auto const & so){return isBetter(so, sss);})) {
                //updateFree(sss, base_w_key);
                unsigned i_tmp = 0, n_tmp = tmp.size();
                while (i_tmp < n_tmp) {
                  if (isBetter(sss, tmp[i_tmp])) tmp[i_tmp] = std::move(tmp[--n_tmp]);
                  else ++i_tmp;
                }
                tmp.resize(n_tmp);
                tmp.emplace_back(std::move(sss));
              }
          }
          //test sur les nouveaux solvers que je veux ajouter à toprocess
          //je vire ceux qui en contiennent d'autres/sont meilleurs que d'autres
          //s.printSolver();
          done.emplace_back(std::move(s));
          /* for (auto const & s1 : done) {
               unsigned i = 0, n = tmp.size();
               while (i < n) {
                   if (isBetter(s1, tmp[i])) tmp[i] = std::move(tmp[--n]);
                   else ++i;
               }
               tmp.resize(n);
           }

          for (auto const & s1 : toprocess) {
              unsigned i = 0, n = tmp.size();
              while (i < n) {
                  if (isBetter(s1, tmp[i])) tmp[i] = std::move(tmp[--n]);
                  else ++i;
              }
              tmp.resize(n);
          }

          for (auto const & s1 : tmp) {
              unsigned i = 0, n = done.size();
              while (i < n) {
                  if (isBetter(s1, done[i])) done[i] = std::move(done[--n]);
                  else ++i;
              }
              done.resize(n);
          }

          for (auto const & s1 : tmp) {
              unsigned i = 0, n = toprocess.size();
              while (i < n) {
                  if (isBetter(s1, toprocess[i])) toprocess[i] = std::move(toprocess[--n]);
                  else ++i;
              }
              toprocess.resize(n);
          }*/
          {
            unsigned i = 0, n = tmp.size();
            while (i < n) {
                auto const & tmpi = tmp[i];
                if (any_of(done.begin(), done.end(), [&tmpi, best_time](auto const & s1) {return isBetter(s1, tmpi);})) tmp[i] = std::move(tmp[--n]);
                else ++i;
            }
            tmp.resize(n);
          }
          {
            unsigned i = 0, n = tmp.size();
            while (i < n) {
                auto const & tmpi = tmp[i];
                if (any_of(toprocess.begin(), toprocess.end(), [&tmpi, best_time](auto const & s1) {return isBetter(s1, tmpi);})) tmp[i] = std::move(tmp[--n]);
                else ++i;
            }
            tmp.resize(n);
          }
          {
            unsigned i = 0, n = done.size();
            while (i < n) {
                auto const & donei = done[i];
                if (any_of(tmp.begin(), tmp.end(), [&donei, best_time](auto const & s1) {return isBetter(s1, donei);})) done[i] = std::move(done[--n]);
                else ++i;
            }
            done.resize(n);
          }
          {
            unsigned i = 0, n = toprocess.size();
            while (i < n) {
                auto const & toprocessi = toprocess[i];
                if (any_of(tmp.begin(), tmp.end(), [&toprocessi, best_time](auto const & s1) {return isBetter(s1, toprocessi);})) toprocess[i] = std::move(toprocess[--n]);
                else ++i;
            }
            toprocess.resize(n);
          }

          for (auto & s1 : tmp) {
              // cout << "s1 (" << s1.nbSols() << "|" << s1.timeON() << "): "; for (auto x : s1.sboxesFromP()) cout << x << " ";
              // for (auto x : s1.sboxesFromC()) cout << x << " ";
              // cout << " | "; for (auto x : s1.keyBits()) cout << x << " ";
              // cout << endl;
              toprocess.emplace_back(std::move(s1));
          }

          //cout << "to process: " << endl;
          //for (auto const & s1 : toprocess) s1.printSolver();
          // cout << "done: " << endl;
          // for (auto const & s1 : done) s1.printSolver();
          // getchar();

          //if (!tmp.empty()) getchar();
      }
      break;
    }

    cout << "done" << endl;
    cout << "done: " << endl;
    for (auto const & s1 : done) s1.printSolver();
    getchar();
    getchar();

    return pc;
}

#endif

/*****
Solver searchBestSolver2(Cipher c) {
  auto toprocess = generateBaseAndKeySolversSpecial(c);

  toprocess.emplace_back();

  cout << "back: " << toprocess.back().timeON() << endl;


  Solver final;
  cout << "nbsol: " << final.nbSols() << " " << endl;
  for (auto const & s : toprocess) final = merge(final,s);
  cout << "nbsol: " << final.nbSols() << " " << endl;
  cout << "nbvar: " << final.sboxesFromP().size() + final.sboxesFromC().size() + final.keyBits().size() << " " << endl;
  auto nvar = final.sboxesFromP().size() + final.sboxesFromC().size() + final.keyBits().size();
  cout << final << endl;
  getchar();

  mergePrint(final, final);


  {
    map<double, unsigned> mymap;
    for (auto const & s : toprocess) mymap[s.nbSols()] += 1;
    for (auto const & p : mymap) cout << p.first << ": " << p.second << endl;
    getchar();
  }

  {
    vector<Solver> tmp;
    while (!toprocess.empty()) {
      auto s = std::move(toprocess.back());
      toprocess.pop_back();
      if (any_of(tmp.begin(), tmp.end(), [&s](auto const & ss){return isBetter(ss,s);})) continue;
      unsigned i = 0, n = tmp.size();
      while (i < n) {
        if (isBetter(s, tmp[i])) tmp[i] = std::move(tmp[--n]);
        else ++i;
      }
      tmp.resize(n);
      tmp.emplace_back(std::move(s));
    }
    swap(tmp, toprocess);
    cout << "toprocess: " << toprocess.size() << endl;
    cout << "tmp: " << tmp.size() << endl;
  }

  cout << "toprocess: " << toprocess.size() << endl;

  map<unsigned, vector<Solver>> mapP;
  map<unsigned, vector<Solver>> mapC;

  Solver PC;

  for (auto const & s : toprocess) {
    for (auto const & x : s.sboxesFromP()) {mapP[x].emplace_back(s); if ((x*c.getLenSB())/c.getSizeBlock() == 0) mapP[x].emplace_back(merge(s,PC));}
    for (auto const & x : s.sboxesFromC()) {mapC[x].emplace_back(s); if ((x*c.getLenSB())/c.getSizeBlock() == c.getNrR() - 1) mapC[x].emplace_back(merge(s,PC));}
  }

  bool flag_cont = true;
  while (flag_cont) {
    flag_cont = false;
    for (unsigned r = 1; r < c.getNrSBp(); ++r) {

    }
  }


  vector<Solver> done;
  while (!toprocess.empty()) {
    unsigned ind = 0;
    double maxtime = 0.0;
    for (unsigned i = 1; i < toprocess.size(); ++i) {
      if (isFaster(toprocess[i],toprocess[ind])) ind = i;
      else if (toprocess[i].timeON() > maxtime) maxtime = toprocess[i].timeON();
    }
    auto s = std::move(toprocess[ind]);
    if (s.sboxesFromP().size() + s.sboxesFromC().size() + s.keyBits().size() == nvar) return s;
    cout << "\r" << toprocess.size() << " - " << s.timeON() << " | " << s.nbSols() << " " << maxtime << " " << flush;
    toprocess[ind] = std::move(toprocess.back());
    toprocess.pop_back();
    vector<Solver> tmp;
    for (auto const & ss : done) {
      if (!ss.dependOnPC() && !s.dependOnPC()) continue;
      auto sss = merge(ss, s);
      if (!isBetter(ss,sss) && !isBetter(s,sss)) {
        bool flag = false;
        if (ss.dependOnPC() && s.dependOnPC() && ss.nbSols() + s.nbSols() - c.getNpairs() > sss.nbSols()) flag = true;
        else if (ss.dependOnPC() && !s.dependOnPC() && ss.nbSols() + s.nbSols() > sss.nbSols()) flag = true;
        else if (!ss.dependOnPC() && s.dependOnPC() && ss.nbSols() + s.nbSols() > sss.nbSols()) flag = true;
        if (flag && none_of(tmp.begin(), tmp.end(), [&sss](auto const & so){return isBetter(so, sss);})) {
          tmp.emplace_back(std::move(sss));
        }
      }
    }
    done.emplace_back(std::move(s));
    for (auto const & s1 : done) {
      unsigned i = 0, n = tmp.size();
      while (i < n) {
        if (isBetter(s1, tmp[i])) tmp[i] = std::move(tmp[--n]);
        else ++i;
      }
      tmp.resize(n);
    }
    for (auto const & s1 : toprocess) {
      unsigned i = 0, n = tmp.size();
      while (i < n) {
        if (isBetter(s1, tmp[i])) tmp[i] = std::move(tmp[--n]);
        else ++i;
      }
      tmp.resize(n);
    }
    for (auto const & s1 : tmp) {
      unsigned i = 0, n = done.size();
      while (i < n) {
        if (isBetter(s1, done[i])) done[i] = std::move(done[--n]);
        else ++i;
      }
      done.resize(n);
    }
    for (auto const & s1 : tmp) {
      unsigned i = 0, n = toprocess.size();
      while (i < n) {
        if (isBetter(s1, toprocess[i])) toprocess[i] = std::move(toprocess[--n]);
        else ++i;
      }
      toprocess.resize(n);
    }
    for (auto & s1 : tmp) {
      // cout << "s1 (" << s1.nbSols() << "|" << s1.timeON() << "): "; for (auto x : s1.sboxesFromP()) cout << x << " ";
      // for (auto x : s1.sboxesFromC()) cout << x << " ";
      // cout << " | "; for (auto x : s1.keyBits()) cout << x << " ";
      // cout << endl;
      toprocess.emplace_back(std::move(s1));
    }
    //if (!tmp.empty()) getchar();
  }
  unsigned ind = 0;
  unsigned n_ind = done[ind].sboxesFromP().size() + done[ind].sboxesFromC().size() + done[ind].keyBits().size();
  for (unsigned i = 1; i < done.size(); ++i) {
    auto tmp = done[i].sboxesFromP().size() + done[i].sboxesFromC().size() + done[i].keyBits().size();
    if (tmp > n_ind) {
      ind = i;
      n_ind = tmp;
    }
  }

  return done[ind];
}
**/
