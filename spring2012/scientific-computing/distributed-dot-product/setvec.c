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

#include <stdlib.h>
#include <stdio.h>
#include"vectypes.h"

void setvec(
        vectype vtype,     // Type of the vector to set up
        long long *veclen,  // Length of the vector
        double *x,          // The vector 
        long long *rank,    // rank of calling process
        long long *nprocs) // p = number of processes in the communicator
{
	long long i;
    long long vectorlength = (*veclen);
    long long pid = (*rank);
    long long num_procs = (*nprocs);
    int min = -1;
    int max = 1;
    double alternate_double = -1.0;

    long long chunksize = vectorlength/num_procs;
    long long remaining = vectorlength%num_procs;
    
    //adding the reminder to the chunksize;
    if(pid<remaining)
    {
    	chunksize++;
    }
	
    if(vtype == zero)
    {
		for(i = 0; i< chunksize; i++)
		{
           *(x+i) = 0;
        }
    }
    else if(vtype == ones)
    {
        for(i = 0; i< chunksize; i++)
        {
		  *(x+i) = 1;
        }
    }
	else if(vtype == linear)
    {	
		long long linearVal=0;
		if(pid<remaining)
		{
			linearVal = chunksize*pid+1;
		}
		else
		{
			linearVal=chunksize*pid+remaining+1;
		}
		for(i=0; i < chunksize; i++)
		{
			x[i]= linearVal;
			linearVal++;
		}
	}
    else if(vtype == alternating)
    {
		if( (pid-1) < remaining )
		{
			chunksize++;
		}
		if(chunksize%2 == 0)
		{
			alternate_double = 1.0;
		}
		long long start_point=0;
		start_point= vectorlength*pid+1;
		for(i=0; i < vectorlength; i++)
		{
			if(start_point%2 == 0)
			{
				x[i] = 1 * alternate_double;
			}
			else
			{
				x[i] = -1 * alternate_double;
			}
		}
    }
    else if(vtype == randomlocal)
    {
        for(i = 0; i< chunksize; i++)
        {
           *(x+i) = x[i]=((double)rand()/RAND_MAX) * 2 - 1;
        }
    }
} 
