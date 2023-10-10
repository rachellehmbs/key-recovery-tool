#include <map>
#include <set>
//#include <execution>
#include "Search.hpp"

using namespace std;

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


    cout << "The basic solvers have been created, printed if you pressed 1, and put in res." << endl;
    cout << endl << "Number of basic solvers put in the vector res :  " << res.size() << endl;

    for (auto const & s : res) s.printSolver();

    return res;
}

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
      if (s2.nbVars() == s1.nbVars() + s.nbVars()) continue;
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
    if (ss.nbStateVars() == 0) continue;
    auto s2 = merge(s, ss);
    if (s2.nbSols() > s.nbSols() + 0.001) continue;
    if (s2.nbVars() == s.nbVars()) continue;
    s = move(s2);
    return updateFree(s, base);
  }
  for (auto const & ss : base) {
    if (ss.nbStateVars() != 0) continue;
    auto s2 = merge(s, ss);
    if (s2.nbSols() > s.nbSols() + 0.001) continue;
    if (s2.nbVars() == s.nbVars()) continue;
    s = move(s2);
    return updateFree(s, base);
  }
}

Solver searchBestSolver(Cipher c, double bound_time, double bound_mem, double bound_off) {
    auto toprocess = generateBaseAndKeySolversSpecial(c); //toprocess is a vector of the basic solvers with PC = 0

    for (auto const & s : toprocess) {
      if (s.timeOFF() > bound_off) bound_off = s.timeOFF() + 0.001;
    }

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
        if (toprocess[i].nbStateVars() == 0) {
          auto s = merge(pc, toprocess[i]);
          if (s.nbSols() <= pc.nbSols() + 0.001) {
            toprocess[i] = toprocess[--n];
            if (s.nbVars() > pc.nbVars()) pc = move(s);
            flag = true;
            break;
          }
          else ++i;
        }
        else ++i;
      }
      if (!flag) {
        i = 0;
        while (i < n) {
          if (toprocess[i].nbStateVars() != 0) {
            auto s = merge(pc, toprocess[i]);
            if (s.nbSols() <= pc.nbSols() + 0.001) {
              toprocess[i] = toprocess[--n];
              if (s.nbVars() > pc.nbVars()) pc = move(s);
              flag = true;
              break;
            }
            else ++i;
          }
          else ++i;
        }
      }
      toprocess.resize(n);
    }
    cout << c.getNpairs() - pc.nbSols() << endl;

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
          else if (tmp2[i].nbVars() > tmp2[ind].nbVars()) ind = i;
          else if (tmp2[i].nbSols() != tmp2[ind].nbSols()) {
            if (tmp2[i].nbSols() < tmp2[ind].nbSols()) ind = i;
          }
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
      if (bound_time <= -100.0) bound_time = s.timeON() + 0.001;
      else bound_time = min(bound_time, s.timeON() + 0.001);
      if (bound_mem <= 0.0) bound_mem = bound_time;
      //if (bound_mem <= s.mem()) bound_mem = s.mem() + 0.001;
    }

    vector<Solver> base_sbox;
    for (auto const & s : toprocess) {
      if (s.nbStateVars() == 1) base_sbox.emplace_back(s);
    }
    auto base_all = toprocess;

    toprocess.clear();

    vector<vector<unsigned>> my_relations (base_sbox.size());
    vector<Solver> head_P, head_C;

    vector<Solver> done;

    vector<Solver> maybe;

    cout << "Generating Tables (Pre computation): " << flush;

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
          //toprocess.emplace_back(si);
          addOff(done, si, bound_off);
          if (!si.sboxesFromP().empty()) head_P.emplace_back(si);
          else if (!si.sboxesFromC().empty()) head_C.emplace_back(si);
        }
        else {
            addOff(done, sij, bound_off);
        }
      }
    }
    for (auto const & s : maybe) {
      bool flag = false;
      for (auto const & ss : done) {
        auto sss = merge(s,ss);
        if (sss.nbVars() == ss.nbVars()) {flag = true; break;}
      }
      if (!flag) addOff(done, s, bound_off);
    }


    vector<vector<Solver>> related_P (head_P.size()), related_C (head_C.size());
    for (auto const & s : base_sbox) {
      if (!s.sboxesFromP().empty()) {
        for (unsigned i = 0; i < head_P.size(); ++i) {
          auto const & ss = head_P[i];
          if (ss.sboxesFromP()[0] <= s.sboxesFromP()[0]) continue;
          auto sss = merge(ss, s);
          if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001 && sss.timeOFF() <= bound_off) addOff(done, sss, bound_off);
        }
      }
      else if (!s.sboxesFromC().empty()) {
        for (unsigned i = 0; i < head_C.size(); ++i) {
          auto const & ss = head_C[i];
          if (ss.sboxesFromC()[0] >= s.sboxesFromC()[0]) continue;
          auto sss = merge(ss, s);
          if (sss.nbSols() < ss.nbSols() + s.nbSols() - 0.001 && sss.timeOFF() <= bound_off) addOff(done, sss, bound_off);
        }
      }
    }

    cout << "done" << endl;


    for (auto const & s : base_all) if (s.nbStateVars() == 0) toprocess.emplace_back(s);


    toprocess.emplace_back(pc);

    if (bound_mem < bound_off) {
      cout << "bound pre > bound mem --> increasing bound_mem!" << endl;
      bound_mem = bound_off;
    }

    cout << bound_time << " - " << bound_mem << " - " << bound_off << endl;

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
          for (auto const & ss : done) {
              if (flag_fast_off && !ss.dependOnPC() && !s.dependOnPC()) continue; //j'autorise merge que si au moins 1 des 2 a PC = 1
              //if (ss.dependOnPC() && s.dependOnPC()) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() != 1 && s.nbStateVars() != 1) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && ss.nbStateVars() == 1 && ss.nbSols() > 2*nbbitssbox - 1) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && s.nbStateVars() == 1 && s.nbSols() > 2*nbbitssbox - 1) continue;
              auto sss = merge(ss, s);
              if (sss.nbSols() > bound_time) continue;
              if (!ss.dependOnPC() && !s.dependOnPC() && sss.timeOFF() > bound_off) continue;
              if (sss.getDST() == 0) continue;
              if ((sss.nbVars() == ss.nbVars() && sss.dependOnPC() == ss.dependOnPC()) || (sss.nbVars() == s.nbVars() && sss.dependOnPC() == s.dependOnPC())) continue;
              bool flag = false;
              if (sss.nbSols() <= ss.nbSols() + 0.1 && sss.timeON() <= ss.timeON() + 0.001) flag = true;
              else if (sss.nbSols() <= s.nbSols() + 0.1 && sss.timeON() <= s.timeON() + 0.001) flag = true;
              else if (ss.dependOnPC() != s.dependOnPC() && sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              else if ((!ss.dependOnPC() || !s.dependOnPC()) && sss.nbSols() + 0.001 < ss.nbSols() + s.nbSols()) flag = true;
              if (flag && none_of(tmp.begin(), tmp.end(), [&sss, best_time](auto const & so){return isBetterNoMem(so, sss);})) {
                sss = refine(sss);
                if (sss.mem() > bound_mem || sss.timeOFF() > bound_off) continue;
                unsigned i_tmp = 0, n_tmp = tmp.size();
                while (i_tmp < n_tmp) {
                  if (isBetterNoMem(sss, tmp[i_tmp])) tmp[i_tmp] = std::move(tmp[--n_tmp]);
                  else ++i_tmp;
                }
                tmp.resize(n_tmp);
                tmp.emplace_back(std::move(sss));
              }
          }
          done.emplace_back(std::move(s));
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
              
              toprocess.emplace_back(std::move(s1));
          }
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
