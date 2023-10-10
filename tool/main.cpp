#include "main.hpp"
#include "Search.hpp"

using namespace std ;

Cipher Solver::cipher;

int main(int argc, char **argv){
    ifstream ifCipher(argv[1]);
    double bound_time = -101.0;
    double bound_off = -1.0;
    double bound_mem = -101.0;
    bool be_slow = false;
    int u = 2;
    while (argc > u) {
      if (string(argv[u]) == "--time" || string(argv[u]) == "-t") {bound_time = 100.0 + stod(argv[u+1]); u += 2;}
      else if (string(argv[u]) == "--mem" || string(argv[u]) == "-m") {bound_mem = stod(argv[u+1]); u += 2;}
      else if (string(argv[u]) == "--pre" || string(argv[u]) == "-p") {bound_off = stod(argv[u+1]); u += 2;}
      else if (string(argv[u]) == "--underN") {be_slow = true; u += 1;}
    }
    if(ifCipher){
        Cipher myCipher(ifCipher,100, be_slow);
        cout << "**** Step 1 : The program has read information on the Cipher. If you press 1, it will print said information.";
        int print = getchar();
        if (print == 49){
            cout << myCipher;
            getchar();
        }
        auto S = searchBestSolver(myCipher, bound_time, bound_mem, bound_off);

        printSolverInFile("result.gv", refine(S));
    }
    else
        cout << "ERREUR: impossible d'ouvrir le fichier." << endl;
    ifCipher.close();
    return 0;
}
