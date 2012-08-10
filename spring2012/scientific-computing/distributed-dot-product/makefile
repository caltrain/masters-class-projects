# This makefile is not complete yet, but is a starting point to use for
# the final project in B673, Spring 2012.
#
# Note that this uses openmpi-1.2.6-gcc, not version 1.3.1 as was used
# in earlier assignments.
#
ALL: default
##### User configurable options #####

MPIR_HOME   = /san/mpi/openmpi-1.2.6-gcc
# Doing "which mpirun" should give the path /usr/mpi/gcc/openmpi-1.2.6/bin/mpirun
CC          = $(MPIR_HOME)/bin/mpicc
CLINKER     = $(MPIR_HOME)/bin/mpicc
CCC         = $(MPIR_HOME)/bin/mpiCC
CCLINKER    = $(CCC)
F77         = $(MPIR_HOME)/bin/mpif77
FLINKER     = $(MPIR_HOME)/bin/mpif77
F90         = $(MPIR_HOME)/bin/mpif90
OPTFLAGS    =  -O3 -I.

### End User configurable options ###

SHELL = /bin/sh

PROFLIB =
CFLAGS  = $(OPTFLAGS) 
CCFLAGS = $(CFLAGS)
FFLAGS = $(OPTFLAGS)
# Use LIBS to add any special libraries for C programs (such as -lm)
LIBS = 
# Use FLIBS to add any special libraries for Fortran programs
FLIBS = 
# Name of your executable goes next:
EXECS = go
OTHEREXECS = 
default: $(EXECS)

# Here is where you put the usual makefile compilation lines.
go: testdot.o elapsedtime.o globaldotproduct.o ddot.o setvec.o  
	$(CC) $(OPTFLAGS) -o go testdot.o  $(LIBS) 
testdot.o: testdot.c 
	$(CC) $(OPTFLAGS) -c testdot.c
setvec.o: setvec.c 
	$(CC) $(OPTFLAGS) -c setvec.c
ddot.o: ddot.c	
	$(CC) $(OPTFLAGS) -c ddot.c
globaldotproduct.o: globaldotproduct.c
	$(CC) $(OPTFLAGS) -c globaldotproduct.c
elapsedtime.o: elapsedtime.c	
	$(CC) $(OPTFLAGS) -c elapsedtime.c

# Some systems have no test for a symbolic link and return false for
# a link that exists
mpif.h: $(MPIR_HOME)/include/mpif.h
	if test \! -f mpif.h ; then \
	    /bin/rm -f mpif.h ; \
	    ln -s $(MPIR_HOME)/include/mpif.h . ; \
	fi
clean:
	rm -f *.o go 

# Beware: this also removes any existing data from previous run(s)
kleen:
	rm -f *.o go results  
