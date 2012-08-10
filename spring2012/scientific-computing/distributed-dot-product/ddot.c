#include<stdio.h>

double ddot(
        long long *veclen,  // Length of the vectors
        double *x,          // The first vector 
        long long *incx,    // Stride in x vector (assume it is always 1)
        double *y,          // The second vector 
        long long *incy)   // Stride in y vector (assume it is always 1)
{
	double localSum = 0.0;
	long long i = 0;
	
	//loop running for the length of the vector.
	for(i=0; i<(*veclen) ; i++)
	{
		localSum = localSum + ( x[i] * y[i] );
	}
	
	//local sum computed and returned. 
	return localSum;
}
