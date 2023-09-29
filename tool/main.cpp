#include "main.hpp"
#include "Search.hpp"

using namespace std ;

Cipher Solver::cipher;

int main(int argc, char **argv){
    ifstream ifCipher(argv[1]);
    if(ifCipher){
        Cipher myCipher(ifCipher,100);
        cout << "**** Step 1 : The program has read information on the Cipher. If you press 1, it will print said information.";
        int print = getchar();
        if (print == 49){
            cout << myCipher;
            getchar();
        }
        auto S = searchBestSolver(myCipher);
        //auto S = searchBestSolverPar(myCipher);

        printSolverInFile("result.gv", S);
        //cout << S << endl;
    }
    else
        cout << "ERREUR: impossible d'ouvrir le fichier." << endl;
    ifCipher.close();
    return 0;
}
