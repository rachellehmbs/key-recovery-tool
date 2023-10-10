#include <algorithm>
#include <set>
#include <map>
#include "Matrix.hpp"

using namespace std;

Matrix::Matrix(std::vector<std::vector<unsigned>> v) { // constructor from system of equations (F2)
  for (auto & eq : v) sort(eq.begin(), eq.end());
  for (unsigned i = 0; i < v.size(); ++i) {
    if (v[i].empty()) continue;
    for (unsigned j = 0; j < v.size(); ++j) {
      if (j == i) continue;
      if (binary_search(v[j].begin(), v[j].end(), v[i][0])) {
        vector<unsigned> tmp;
        tmp.reserve(v[i].size() + v[j].size());
        unsigned k1 = 0, k2 = 0;
        while (k1 < v[i].size() && k2 < v[j].size()) {
          if (v[i][k1] < v[j][k2]) tmp.emplace_back(v[i][k1++]);
          else if (v[i][k1] > v[j][k2]) tmp.emplace_back(v[j][k2++]);
          else {++k1; ++k2;}
        }
        for (; k1 < v[i].size(); ++k1) tmp.emplace_back(v[i][k1]);
        for (; k2 < v[j].size(); ++k2) tmp.emplace_back(v[j][k2]);
        v[j] = std::move(tmp);
      }
    }
  }

  map<unsigned, unsigned> allvariables;
  nblines = 0; nbcols = 0;
  for (auto const & eq : v) {
    if (eq.empty()) continue;
    auto it = allvariables.find(eq[0]);
    if (it == allvariables.end()) allvariables[eq[0]] = nblines++;
    for (unsigned i = 1; i < eq.size(); ++i) {
      it = allvariables.find(eq[i]);
      if (it == allvariables.end()) allvariables[eq[i]] = nbcols++;
    }
  }
  space = vector<uint8_t> (nbcols*nblines, 0);
  lines = vector<uint8_t *> (nblines);
  front = vector<unsigned> (nblines);
  columns = vector<unsigned> (nbcols, ~0u);
  unsigned l = 0;
  for (auto const & eq : v) {
    if (eq.empty()) continue;
    front[l] = eq[0];
    lines[l] = space.data() + l*nbcols;
    for (unsigned i = 1; i < eq.size(); ++i) {
      columns[allvariables[eq[i]]] = eq[i];
      lines[l][allvariables[eq[i]]] = 1;
    }
    ++l;
  }


}

Matrix::Matrix(Matrix const & mat) : nbcols (mat.nbcols), nblines (mat.nblines),
 front (mat.front), columns (mat.columns), space (mat.nblines*mat.nbcols), lines (mat.nblines) {
   for (unsigned l = 0; l < nblines; ++l) {
     lines[l] = space.data() + l*nbcols;
     for (unsigned c = 0; c < nbcols; ++c) lines[l][c] = mat(l,c);
   }
}


Matrix & Matrix::operator=(Matrix const & mat) {
  nbcols = mat.nbcols;
  nblines = mat.nblines;
  front = mat.front;
  columns = mat.columns;
  space = vector<uint8_t>(nblines*nbcols);
  lines = vector<uint8_t *> (nblines);
  for (unsigned l = 0; l < nblines; ++l) {
    lines[l] = space.data() + l*nbcols;
    for (unsigned c = 0; c < nbcols; ++c) lines[l][c] = mat(l,c);
  }
  return *this;
}

void Matrix::swapLineColumn(unsigned l, unsigned c) {
  (*this)(l,c) = 0;
  for (unsigned i = 0; i < nblines; ++i) {
    if ((*this)(i,c) == 0) continue;
    for (unsigned j = 0; j < nbcols; ++j) (*this)(i,j) ^= (*this)(l,j);
    (*this)(i,c) = 1;
  }
  (*this)(l,c) = 1;
  swap(front[l], columns[c]);
}

bool Matrix::isKnown(unsigned x) {
  for (unsigned i = 0; i < nblines; ++i) {
    if (front[i] != x) continue;
    for (unsigned j = 0; j < nbcols; ++j) if ((*this)(i,j) != 0) return false;
    return true;
  }
  return false;
}

// compute rank of the submatrix involving only variables from the input
unsigned Matrix::computeRank(vector<unsigned> const & vars, bool sorted) {
  if (!sorted) {
    auto tmp = vars;
    sort(tmp.begin(), tmp.end());
    return computeRank(tmp, true);
  }
  unsigned rank = 0;
  for (unsigned i = 0; i < nblines; ++i) {
    if (!binary_search(vars.begin(), vars.end(), front[i])) continue;
    unsigned j = 0;
    while (j < nbcols && ((*this)(i,j) == 0 || binary_search(vars.begin(), vars.end(), columns[j]))) ++j;
    if (j == nbcols) rank += 1;
    else swapLineColumn(i,j);
  }
  return rank;
}

Matrix Matrix::extract(std::vector<unsigned> const & vars) {
  if (!is_sorted(vars.begin(), vars.end())) {
    auto tmp = vars;
    sort(tmp.begin(), tmp.end());
    return extract(tmp);
  }
  Matrix res;
  res.nblines = res.nbcols = 0;
  map<unsigned, unsigned> allvars;
  for (unsigned i = 0; i < nblines; ++i) {
    if (!binary_search(vars.begin(), vars.end(), front[i])) continue;
    unsigned j = 0;
    while (j < nbcols && ((*this)(i,j) == 0 || binary_search(vars.begin(), vars.end(), columns[j]))) ++j;
    if (j == nbcols) {
      res.nblines += 1;
      for (j = 0; j < nbcols; ++j) {
        if ((*this)(i,j) == 0) continue;
        auto it = allvars.find(columns[j]);
        if (it == allvars.end()) allvars[columns[j]] = res.nbcols++;
      }
    }
    else swapLineColumn(i,j);
  }
  res.space = vector<uint8_t> (res.nblines * res.nbcols);
  res.lines = vector<uint8_t *> (res.nblines);
  res.front = vector<unsigned> (res.nblines);
  res.columns = vector<unsigned> (res.nbcols);
  for (auto const & p : allvars) res.columns[p.second] = p.first;
  unsigned l = 0;
  for (unsigned i = 0; i < nblines; ++i) {
    if (!binary_search(vars.begin(), vars.end(), front[i])) continue;
    res.lines[l] = res.space.data() + l*res.nbcols;
    res.front[l] = front[i];
    for (unsigned j = 0; j < nbcols; ++j) {
      if ((*this)(i,j) != 0) res.lines[l][allvars[columns[j]]] = 1;
    }
    ++l;
  }
  return res;
}

ostream& operator<<(std::ostream & flux, Matrix const & mat) {
  unsigned const & nbits = 16;
  cout << "lines: " << mat.nblines << ", columns: " << mat.nbcols << endl;
  for (unsigned i = 0; i < mat.nblines; ++i) {
    flux << "k" << mat.front[i]/nbits << "[" << mat.front[i]%nbits << "]";
    for (unsigned j = 0; j < mat.nbcols; ++j) {
      if (mat.lines[i][j] != 0) flux << " + k" << mat.columns[j]/nbits << "[" << mat.columns[j]%nbits << "]";
    }
    flux << endl;
  }
  return flux;
}
