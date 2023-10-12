    //
    //  Cipher.cpp
    //
    //
#include <set>
#include "Cipher.hpp"
using namespace std;

ostream& operator<<(ostream & flux, Cipher const & c) {
    flux << "SB :" << endl;
    flux << "len of sbox in bits = " << c.lenSB << endl;
    for (unsigned i = 0; i < c.sizeSB; i++)
        flux << c.SB[i] << " ";



    flux << endl << endl << endl << "PERMutation :" << endl;
    for (unsigned i = 0; i < c.sizeBlock; i++){
        cout << c.PERM[i] << " ";
    }

    flux << endl << endl << "block size = " << c.sizeBlock << endl << endl;
    {
        flux << "DDT :" << endl;
        for (int din = 0; din < c.sizeSB; din++){
            for (int dout = 0; dout < c.sizeSB; dout++)
                flux << c.DDT[din][dout] << " ";
            flux << endl;
        }
    }
    flux << endl << "nr rounds = " << c.nrR << endl << endl << "DINa :" << endl;
    for (unsigned i = 0; i < c.sizeBlock; i++){
        if (c.DINa[i] == 2)
            flux << "*";
        else
            flux << c.DINa[i];
    }
    flux << endl << endl << "DINb :" << endl;
    for (unsigned i = 0; i < c.sizeBlock; i++){
        if (c.DINb[i] == 2)
            flux << "*";
        else
            flux << c.DINb[i];
    }
    flux << endl << endl << "DOUTb:" << endl;
    for (unsigned i = 0; i < c.sizeBlock; i++){
        if (c.DOUTb[i] == 2)
            flux << "*";
        else
            flux << c.DOUTb[i];
    }
    flux << endl << endl << "DOUTa :" << endl;
    for (unsigned i = 0; i < c.sizeBlock; i++){
        if (c.DOUTa[i] == 2)
            flux << "*";
        else
            flux << c.DOUTa[i];
    }
    flux << endl << endl << "DKEY :" << endl;
    for (unsigned i = 0; i < c.sizeBlock*(c.nrR+1); i++){
        if (c.DKEY[i] == 2)
            flux << "*";
        else
            flux << c.DKEY[i];
    }
    flux << endl << endl << "nrSBp = " << c.nrSBp << ", nrSBc = " << c.nrSBc << endl << endl;
    return flux;
}

Cipher::Cipher(ifstream & input_file, double N, bool be_slow) : beslow(be_slow), Npairs (N) {
    string temp;
    string temp2;
    istringstream buffer;
    unsigned i;
    while(getline(input_file, temp)){
            //SB
        if( temp.rfind("SB", 0) == 0){

            for (i = 0; i < 2; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp); //pour pouvoir itérer après dessus
            SB = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>()); //trouver les unsigned et les mettre ds le vecteur SB
            sizeSB = (SB).size();
            lenSB = log2(sizeSB);
        }
            //PERM
        else if( temp.rfind("PERM", 0) == 0 ){
            for (i = 0; i < 4; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            PERM = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>());
            sizeBlock = (PERM).size();

        }
            //nrR
        else if( temp.rfind("nrR", 0) == 0 ){
            for (i = 0; i < 3; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            nrR = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>())[0];
        }
            //DINb
        else if( temp.rfind("DINb", 0) == 0 ){
            for (i = 0; i < 4; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            DINb = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>());

        }
            //DINa
        else if( temp.rfind("DINa", 0) == 0 ){
            for (i = 0; i < 4; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            DINa = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>());
        }
            //DOUTb
        else if( temp.rfind("DOUTb", 0) == 0 ){
            for (i = 0; i < 5; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            DOUTb = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>());
        }
            //DOUTa
        else if( temp.rfind("DOUTa", 0) == 0 ){
            for (i = 0; i < 5; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            DOUTa = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>());
        }
            //DKEY
        else if( temp.rfind("DKEY", 0) == 0 ){
            for (i = 0; i < 4; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            DKEY = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>());
        }
            //nrSBp
        else if( temp.rfind("nrSBp", 0) == 0 ){
            for (i = 0; i < 5; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            nrSBp = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>())[0];
        }
            //nrSBc
        else if( temp.rfind("nrSBc", 0) == 0 ){
            for (i = 0; i < 5; i++)
                temp.erase(temp.begin());
            buffer = istringstream(temp);
            nrSBc = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>())[0];
        }
            //KS
        else if (temp.rfind("KS",0) == 0)
            getKS(input_file);
    }

    if (DKEY.empty()) DKEY = vector<unsigned>((nrR + 1)*sizeBlock, 0);

    InvPERM = vector<unsigned>(sizeBlock);
    for (unsigned i = 0; i < sizeBlock; i++)
        InvPERM[PERM[i]] = i;

    matKS = Matrix(KS);

    knownkeybits = vector<uint8_t> (sizeBlock*(nrR + 1));
    for (unsigned i = 0; i < sizeBlock*(nrR + 1); ++i) knownkeybits[i] = matKS.isKnown(i);

    computeDDT();
    propagation();
    fillSb();

    getchar();



    relatedSboxes = vector<vector<unsigned>> (nrR*sizeBlock/lenSB);

    for (unsigned r = 0; r < nrSBp; ++r) {
      for (unsigned i = 0; i < sizeBlock; ++i) {
          auto s = (r+1)*(sizeBlock/lenSB) + (PERM[i]/lenSB);
          relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(s);
          for (unsigned l = 0; l < lenSB; ++l) {
              relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(r*(sizeBlock/lenSB) + InvPERM[(PERM[i]/lenSB)*lenSB + l]/lenSB);
          }
          if (r > 0) {
            auto s = (r-1)*(sizeBlock/lenSB) + (InvPERM[i]/lenSB);
            relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(s);
            for (unsigned l = 0; l < lenSB; ++l) {
              relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(r*(sizeBlock/lenSB) + PERM[(InvPERM[i]/lenSB)*lenSB + l]/lenSB);
            }
          }

      }
    }
    for (unsigned r = nrR - nrSBc; r < nrR; r++) {
      for (unsigned i = 0; i < sizeBlock; ++i) {
        auto s = (r-1)*(sizeBlock/lenSB) + (InvPERM[i]/lenSB);
        relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(s);
        for (unsigned l = 0; l < lenSB; ++l) {
          relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(r*(sizeBlock/lenSB) + PERM[(InvPERM[i]/lenSB)*lenSB + l]/lenSB);
        }
        if (r < nrR - 1) {
          auto s = (r+1)*(sizeBlock/lenSB) + (PERM[i]/lenSB);//ok
          relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(s);
          for (unsigned l = 0; l < lenSB; ++l) {
              relatedSboxes[r*(sizeBlock/lenSB) + (i/lenSB)].emplace_back(r*(sizeBlock/lenSB) + InvPERM[(PERM[i]/lenSB)*lenSB + l]/lenSB);
          }
        }
      }
    }
    for (auto & v : relatedSboxes) {
      set<unsigned> s (v.begin(), v.end());
      v.clear();
      for (auto x : s) v.emplace_back(x);

    }

    global_ct = 0;
}

void Cipher::computeDDT() {
    DDT = vector<vector<unsigned>> (sizeSB,vector<unsigned>(sizeSB, 0));
    for (unsigned din = 0; din < sizeSB; din++){
        for (unsigned x = 0; x < sizeSB; x++){
            DDT[din][SB[x] ^ SB[x ^ din]] += 1;
        }
    }
}

void Cipher::getKS(ifstream & input_file){
    KS = vector<vector<unsigned>>() ;

    string temp;
    istringstream buffer;
    vector<unsigned> vect;

    for (;;){ //in line i, we put the ith key schedule equation of the file
        getline(input_file, temp);
        if (temp[0] == 'k'){
            temp.erase(remove(temp.begin(),temp.end(), '+'), temp.end());
            temp.erase(remove(temp.begin(),temp.end(), 'k'), temp.end());
            replace(temp.begin(), temp.end(), '[', ' ');
            replace(temp.begin(), temp.end(), ']', ' ');
            buffer = istringstream(temp);
            vect = vector<unsigned>((istream_iterator<unsigned>(buffer)), istream_iterator<unsigned>());
            vector<unsigned> tmp;
            for (unsigned ct = 0; ct < vect.size(); ct+=2){ //vect.size() is always an even number, vect.size()/2 is equal to the number of key bits appearing in the equation, ie the number of 1 in the vector
                tmp.push_back(vect[ct]*sizeBlock + vect[ct + 1]);
            }
            KS.emplace_back(move(tmp));
        }
        else {
          cout << "Key schedule loaded. It contains " << KS.size() << " equations" << endl;
          return;
        }
    }
}

void Cipher::propagation(){
    unsigned bitsToZero,bitsToOne;
    vector < unsigned > din,dout;
    unsigned bufferSB[lenSB];

    //plaintext
    prop = vector < unsigned > ((2*nrR)*sizeBlock,3);
    for (unsigned i = 0; i < sizeBlock; i++){
        prop[(2*nrSBp-1)*sizeBlock + i] = DINa[i];
        if (nrSBp > 0)
            prop[(2*nrSBp-2)*sizeBlock + i] = DINb[i];
    }

    for (unsigned i = 0; i < nrSBp ; i++){ //we proceed round by round for the rounds before the distinguisher
        unsigned l = nrSBp - 1 - i;
        for (unsigned j = 0; j < sizeBlock/lenSB ; j++){ // one Sbox per iteration
            if (all_of(&prop[(2*l+1)*sizeBlock+j*lenSB], &prop[(2*l+1)*sizeBlock+j*lenSB+lenSB /**il manque - 1???*/], [](unsigned x){return x == 0;})){
                for (unsigned k = 0; k < lenSB; k++){
                    prop[2*l*sizeBlock + j*lenSB + k] = 0;
                }
            }
            else{
                dout = getDiff(2*l+1,j,prop);
                bitsToZero = findBitsToZeroBackward(dout);
                bitsToOne = findBitsToOneBackward(dout);
                for (unsigned k = 0; k < lenSB; k++){
                    if ( (((bitsToZero>>k)&0x1) == 0) ){
                        if (prop[2*l*sizeBlock + j*lenSB + k] == 3)
                            prop[2*l*sizeBlock + j*lenSB + k] = 0;
                    }
                    else if( (((bitsToOne>>k)&0x1) == 1)  ){
                        if (prop[2*l*sizeBlock + j*lenSB + k] == 3)
                            prop[2*l*sizeBlock + j*lenSB + k] = 1;
                    }
                    else{
                        if (prop[2*l*sizeBlock + j*lenSB + k] == 3)
                            prop[2*l*sizeBlock + j*lenSB + k] = 2;
                    }
                }
            }
        }

        if (l != 0){
            for(unsigned j = 0; j < sizeBlock; j++){
                if((prop[2*l*sizeBlock + j] < 2) && (DKEY[l*sizeBlock + j] < 2))
                    prop[(2*l-1)*sizeBlock + InvPERM[j]] = prop[2*l*sizeBlock + j] ^ DKEY[l*sizeBlock+j]; //ok
                else prop[(2*l-1)*sizeBlock + InvPERM[j]] = 2; //ok
            }
        }
    }

        // After the distinguisher

    if (nrSBc > 0) {
      for (unsigned i = 0; i < sizeBlock; i++){
          prop[2*(nrR - nrSBc)*sizeBlock + i] = DOUTb[i];
          if (nrSBc > 0)
              prop[(2*(nrR - nrSBc)+1)*sizeBlock + i] = DOUTa[i];
      }
    }



    for (unsigned i = 0; i < nrSBc ; i++){ //we proceed round by round for the rounds after the distinguisher
        unsigned l = nrR - nrSBc + i;
        for (unsigned j = 0; j < sizeBlock/lenSB ; j++){ // one Sbox per iteration
            if (all_of(&prop[(2*l)*sizeBlock+j*lenSB], &prop[(2*l)*sizeBlock+j*lenSB+lenSB], [](unsigned x){return x == 0;})){
                for (unsigned k = 0; k < lenSB; k++){
                    prop[(2*l+1)*sizeBlock + j*lenSB + k] = 0;
                }
            }
            else{
                dout = getDiff(2*l,j,prop);
                bitsToZero = findBitsToZeroForward(dout);
                bitsToOne = findBitsToOneForward(dout);
                for (unsigned k = 0; k < lenSB; k++){
                    if ( (((bitsToZero>>k)&0x1) == 0) ){
                        if (prop[(2*l+1)*sizeBlock + j*lenSB + k] == 3)
                            prop[(2*l+1)*sizeBlock + j*lenSB + k] = 0;
                    }
                    else if( (((bitsToOne>>k)&0x1) == 1)  ){
                        if (prop[(2*l+1)*sizeBlock + j*lenSB + k] == 3)
                            prop[(2*l+1)*sizeBlock + j*lenSB + k] = 1;
                    }
                    else{
                        if (prop[(2*l+1)*sizeBlock + j*lenSB + k] == 3)
                            prop[(2*l+1)*sizeBlock + j*lenSB + k] = 2;
                    }
                }
            }
        }
        if ((l+1) < nrR){
            for(unsigned j = 0; j<sizeBlock; j++){
                if((prop[(2*l+1)*sizeBlock + j] < 2) && (DKEY[(l+1)*sizeBlock + j] < 2))
                    prop[2*(l+1)*sizeBlock + PERM[j]] = prop[(2*l+1)*sizeBlock + j] ^ DKEY[(l+1)*sizeBlock + j]; //ok
                else prop[2*(l+1)*sizeBlock + PERM[j]] = 2; //ok
            }
        }
    }


}


vector < unsigned > Cipher::getDiff(unsigned i, unsigned j, vector <unsigned> & v) const{
    vector < unsigned > d (lenSB);
    for (unsigned k = 0; k < lenSB; k++)
        d[k] = v[i*sizeBlock + lenSB*j + k];
    return d;
}

unsigned Cipher::findBitsToZeroForward(vector < unsigned > din) const{
    unsigned bitsToZero = 0, i = 0, dout = 0;
    vector < unsigned > possible_din = possibleVectors(din);
    for (i = 0; i < possible_din.size(); i++){
        for (dout = 0; dout < sizeSB; dout++){
            if (DDT[possible_din[i]][dout] != 0)
                bitsToZero |= dout;
        }
    }
    return bitsToZero;
}

unsigned Cipher::findBitsToOneForward(vector < unsigned > din) const{
    unsigned bitsToOne = (sizeSB-1), i = 0, dout = 0;
    vector < unsigned > possible_din = possibleVectors(din);
    for (i = 0; i < possible_din.size(); i++){
        for (dout = 0; dout < sizeSB; dout++){
            if (DDT[possible_din[i]][dout] != 0)
                bitsToOne &= dout;
        }
    }
    return bitsToOne;
}

unsigned Cipher::findBitsToZeroBackward(vector < unsigned > dout) const{
    unsigned bitsToZero = 0;
    vector < unsigned > possible_dout = possibleVectors(dout);
    for (int i = 0; i < possible_dout.size(); i++){
        for (int din = 0; din < sizeSB; din++){
            if (DDT[din][possible_dout[i]] != 0)
                bitsToZero |= din;
        }
    }
    return bitsToZero;
}

unsigned Cipher::findBitsToOneBackward(vector < unsigned > dout) const{
    unsigned bitsToOne = (sizeSB-1), i = 0, din = 0;
    vector < unsigned > possible_dout = possibleVectors(dout);
    for (i = 0; i < possible_dout.size(); i++){
        for (din = 0; din < sizeSB; din++){
            if (DDT[din][possible_dout[i]] != 0)
                bitsToOne &= din;
        }
    }
    return bitsToOne;
}


void Cipher::fillSb(){
    unsigned r,j,ct = 0;
    vector<unsigned> din, dout;
    solSboxes = vector<double> (nrR*(sizeBlock/lenSB), 0.0);
    solSboxesIn = vector<double> (nrR*(sizeBlock/lenSB), 0.0);

    activitySBT = vector<unsigned>(nrR*(sizeBlock/lenSB));
    filterSB = vector<double>(nrR*(sizeBlock/lenSB));


        // For rounds before DeltaX
    for (r = 0; r < nrR; r++){ //for each sb layer before the diff
        for(j = 0;  j < sizeBlock/lenSB; j++){ //for each sb
            int act = 0;
            for(unsigned k = 0; k<lenSB; k++){
                if(prop[2*r*sizeBlock + j*lenSB + k]) act = 1;
            }
            activitySBT[ct] = act;
            ct++;
        }
    }

    ct = 0;

    double save_filter = 0.0;



    for (r = 0; r < nrSBp; r++){ //for each sb layer before the diff
        for(j = 0;  j < sizeBlock/lenSB; j++){ //for each sb
            din = getDiff(2*r,j, prop);
            dout = getDiff(2*r+1,j,prop);
            solSboxes[ct] = log2(getNrSol(din, dout));

            if(activitySBT[ct] == 1){

                vector<pair<unsigned, unsigned>> my_inputs;

                for (unsigned x = 0; x < 1u << lenSB; ++x) {
                  for (unsigned y = 0; y < 1u << lenSB; ++y) {
                    bool add = true;
                    auto diff_in = x^y;
                    for (unsigned b = 0; b < lenSB; ++b) if (din[b] != 2 && ((diff_in >> b) & 1) != din[b]) add = false;
                    auto diff_out = SB[x]^SB[y];
                    for (unsigned b = 0; b < lenSB; ++b) if (dout[b] != 2 && ((diff_out >> b) & 1) != dout[b]) add = false;
                    if (add) my_inputs.emplace_back(x,y);
                  }
                }
                set<unsigned> set_of_inputs;
                unsigned expected_size = 0;
                for (auto const & my_pair : my_inputs) {
                  unsigned x = 0, i = 0;
                  for (unsigned b = 0; b < lenSB; ++b) {
                    if (isKnownKeyBit(r*sizeBlock + j*lenSB + b)) {
                      x |= ((my_pair.first >> b) & 1) << i;
                      i += 1;
                      x |= ((my_pair.second >> b) & 1) << i;
                      i += 1;
                    }
                    else {
                      x |= (((my_pair.first >> b) & 1) ^ ((my_pair.second >> b) & 1)) << i;
                      i += 1;
                    }
                  }
                  expected_size = i;
                  set_of_inputs.emplace(x);
                }
                for (int i = 0; i < lenSB; ++i) if (din[i] != 2) expected_size -= 1;
                double cpt = set_of_inputs.size();
                cpt /= 1u << expected_size;


                solSboxes[ct] -= log2(cpt);
                if (!beslow || r != 0) {
                  filterSB[ct] = -log2(cpt);
                  solSboxesIn[ct] = expected_size - filterSB[ct];
                }
                else {
                  filterSB[ct] = 0;
                  solSboxesIn[ct] = expected_size;
                  Npairs += log2(cpt);
                  save_filter -= log2(cpt);
                }

            }

            ct++;
        }
    }

        // For middle rounds, that are of no interest to us
    for (r = nrSBp; r < nrR - nrSBc; r++){ //for each sb layer before the diff
        for(j = 0;  j < sizeBlock/lenSB; j++){ //for each sb
            solSboxes[ct] = 0;
            ct++;
        }
    }
        // For rounds after DeltaY




    for (r = nrR - nrSBc; r < nrR; r++){ //for each sb after the diff
        for(j = 0;  j < sizeBlock/lenSB; j++){ //for each sb
            din = getDiff(2*r,j,prop);
            dout = getDiff(2*r+1,j,prop);
            solSboxes[ct] = log2(getNrSol(din, dout));

            if(activitySBT[ct] == 1){

              vector<pair<unsigned, unsigned>> my_inputs;

              for (unsigned x = 0; x < 1u << lenSB; ++x) {
                for (unsigned y = 0; y < 1u << lenSB; ++y) {
                  bool add = true;
                  auto diff_in = x^y;
                  for (unsigned b = 0; b < lenSB; ++b) if (din[b] != 2 && ((diff_in >> b) & 1) != din[b]) add = false;
                  auto diff_out = SB[x]^SB[y];
                  for (unsigned b = 0; b < lenSB; ++b) if (dout[b] != 2 && ((diff_out >> b) & 1) != dout[b]) add = false;
                  if (add) my_inputs.emplace_back(SB[x],SB[y]);
                }
              }
              set<unsigned> set_of_inputs;
              unsigned expected_size = 0;
              for (auto const & my_pair : my_inputs) {
                unsigned x = 0, i = 0;
                for (unsigned b = 0; b < lenSB; ++b) {
                  if (isKnownKeyBit((r+1)*sizeBlock + getPERM()[j*lenSB + b])) {
                    x |= ((my_pair.first >> b) & 1) << i;
                    i += 1;
                    x |= ((my_pair.second >> b) & 1) << i;
                    i += 1;
                  }
                  else {
                    x |= (((my_pair.first >> b) & 1) ^ ((my_pair.second >> b) & 1)) << i;
                    i += 1;
                  }
                }
                expected_size = i;
                set_of_inputs.emplace(x);
              }
              for (int i = 0; i < lenSB; ++i) if (dout[i] != 2) expected_size -= 1;
              double cpt = set_of_inputs.size();
              cpt /= 1u << expected_size;

               
                solSboxes[ct] -= log2(cpt);
                if (!beslow || r != nrR - 1) {
                  filterSB[ct] = -log2(cpt);
                  solSboxesIn[ct] = expected_size - filterSB[ct];
                }
                else {
                  filterSB[ct] = 0;
                  solSboxesIn[ct] = expected_size;
                  Npairs += log2(cpt);
                  save_filter -= log2(cpt);
                }
                
            }

            ct++;
        }
    }


    cout << "Filter on N: " << save_filter << endl;
}

unsigned Cipher::getNrSol(vector <unsigned> din, vector < unsigned > dout){
    unsigned nrsol = 0;
    vector < unsigned > possible_dout = possibleVectors(dout);
    vector < unsigned > possible_din = possibleVectors(din);
    for (unsigned i = 0; i < possible_din.size(); i++){
        for (unsigned j = 0; j < possible_dout.size(); j++){
            nrsol += DDT[possible_din[i]][possible_dout[j]];
        }
    }
    return nrsol;
}


vector <unsigned> Cipher::possibleVectors(vector <unsigned> vect) const{
    vector <unsigned> res(1,0);
    for(unsigned b = 0; b < lenSB; ++b){
        if(vect[b] != 2){
            for(auto & x : res) x |= vect[b] << b;
        }
        else{
            auto tmp = res;
            for(auto x : tmp) res.emplace_back(x | (1 << b));
        }
    }
    return res;
}
