//---------------------------------------------------------------------------------
// 
// Initialize a vector to a type specified by vectypes.h. Although each process
// calls this independently and it does not require any interprocess communication,
// setting up the vectors requires knowing the rank of the caller and the number 
// of processes in the communicator group.
// 
// This prototype varies in one important respect: the enum type is passed by
// value, not by address. F2008 has interoperability mechanisms that allow Fortran
// to share enum types with C/C++.
// 
//---------------------------------------------------------------------------------
#include <vectypes.h>
void setvec(
        vectype vtype,     // Type of the vector to set up
        long long *veclen,  // Length of the vector
        double *x,          // The vector 
        long long *rank,    // rank of calling process
        long long *nprocs); // p = number of processes in the communicator
