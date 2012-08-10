
#include <stdlib.h> 
#include<mpi.h>
#include "ddot.c"

void globaldotproduct(
        long long *localn,        // length of local vector segments
        double *localx,           // local segment of vector x
        double *localy,           // local segment of vector y
        double *dotval,           // the value of the dotproduct of the full global x and y
        long long *localrank,     // rank of local process, in range 0 to nprocs-1
        long long *nprocs,        // total number of processes in dotcomm
        MPI_Comm *dotcomm         // pointer to mpi communicator
					  )
{
	long long incx = 1ll;
	long long incy = 1ll;
	long long gather_iteration = 0ll;
	double localsum;
	if( ((int)*localn) != 0)
	{
		localsum = ddot(localn, localx, &incx, localy, &incy);
	}
	MPI_Allreduce(&localsum, dotval, 1, MPI_DOUBLE, MPI_SUM, *dotcomm);
}
