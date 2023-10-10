#ifndef MATRIX_HPP
#define MATRIX_HPP

#include <vector>
#include <iostream>

class Matrix {
public:
  Matrix() : nbcols (0), nblines (0) {};
  Matrix(std::vector<std::vector<unsigned> >); // constructor from system of equations (F2)

  Matrix(Matrix const & m);
  Matrix(Matrix &&) = default;

  Matrix & operator=(Matrix const & m);

  Matrix & operator=(Matrix &&) = default;

  ~Matrix() = default;

  Matrix extract(std::vector<unsigned> const &); //extract subsystem

  bool isKnown(unsigned);

  unsigned computeRank(std::vector<unsigned> const &, bool sorted = false); // compute rank of the submatrix involving only variables from the input

  uint8_t operator()(unsigned i, unsigned j) const {return lines[i][j];}; // access M(i,j);
  uint8_t & operator()(unsigned i, unsigned j) {return lines[i][j];}; // access M(i,j);

  friend std::ostream& operator<<(std::ostream &, Matrix const &); //overload print


private:
  // implementation
  // proposal: keep the matrix in a Gauss-Jordan echelon form

  unsigned nbcols;
  unsigned nblines;

  // "name" of variables
  std::vector<unsigned> front;
  std::vector<unsigned> columns;

  // matrix
  std::vector<uint8_t> space; // full storage, contigus == fast
  std::vector<uint8_t*> lines; // lines of the matrix, ref to space

  void swapLines(unsigned l1, unsigned l2) {std::swap(lines[l1], lines[l2]);}
  void swapLineColumn(unsigned l, unsigned c);

};

#endif
