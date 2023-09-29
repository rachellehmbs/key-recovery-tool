# Generic Makefile for compiling a simple executable.


CC := g++
#CC := icpc
SRCDIR := src
BUILDDIR := build
#CFLAGS := -fast -s -Wall -Wno-unused-variable -std=c++11 -DNDEBUG -opt-multi-version-aggressive -xHost
#CFLAGS := -fast -s -Wall -Wno-unused-variable -std=c++11 -DNDEBUG -opt-multi-version-aggressive -xHost -prof-use -prof-dir=profile/
#CFLAGS := -fast -Wall -Wno-unused-variable -std=c++11 -DNDEBUG -opt-multi-version-aggressive -xHost -prof-gen -prof-dir=profile/
#CFLAGS := -O3 -s -mtune=native -march=native -Wall -Wno-unused-variable -fopenmp -std=c++17 -DNDEBUG
CFLAGS := -O3 -mtune=native -march=native -Wall -Wno-unused-variable -std=c++17 -DNDEBUG
#CFLAGS := -g -Wall -Wno-unused-variable -std=c++17 -DNDEBUG

#LIBS := -lboost_program_options
LIBS := -lm

TARGET := difftool

SOURCES := $(shell find $(SRCDIR) -type f -name *.cpp)
HEADERS := $(shell find $(SRCDIR) -type f -name *.hpp)

OBJECTS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.cpp=.o))

DEPS := $(patsubst $(SRCDIR)/%,$(BUILDDIR)/%,$(SOURCES:.cpp=.deps))


all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo " Linking..."; $(CC) $(USERDEFINES) $(CFLAGS) $^ $(LIBS) -o $(TARGET)



$(BUILDDIR)/%.o: $(SRCDIR)/%.cpp  $(HEADERS)
	@mkdir -p $(BUILDDIR)
	@echo " CC $<"; $(CC) $(USERDEFINES) $(CFLAGS) -MD -MF $(@:.o=.deps) -c -o $@ $<

clean:
	@echo " Cleaning..."; $(RM) -r $(BUILDDIR) $(TARGET) *~

-include $(DEPS)

.FORCE:

.PHONY: clean .FORCE
