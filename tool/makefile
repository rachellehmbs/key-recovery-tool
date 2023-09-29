CC = g++
EXEC = prog

$(EXEC) : main.o Cipher.o
	$(CC) -std=c++17 -o $(EXEC) main.o Cipher.o
	
main.o : main.cpp main.hpp Cipher.cpp Cipher.hpp ##Matrix.hpp Solver.hpp
	$(CC) -std=c++17 -c main.cpp
	
Cipher.o : Cipher.cpp Cipher.hpp
	$(CC) -std=c++17 -c Cipher.cpp

clean :
	rm -rf *.o

mrproper : clean
	rm -rf $(EXEC)
