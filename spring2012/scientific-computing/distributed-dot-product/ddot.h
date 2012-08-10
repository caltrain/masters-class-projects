//---------------------------------------------------------------------------------
//
// Compute the dotproduct of two vectors x and y of doubles.  Beware that the
// length is passed in as a pointer to an integer, instead of by value. See notes
// from last two lecures in class to find out why.
// 
// This uses the BLAS convention of also passing in strides for the vectors,
// but this only needs to work for both strides = 1.  Using the same interface
// as BLAS allows shifting to them later, and more importantly masks against
// accidentally linking to them.
//
//---------------------------------------------------------------------------------
double ddot(
        long long *veclen,  // Length of the vectors
        double *x,          // The first vector 
        long long *incx,    // Stride in x vector (assume it is always 1)
        double *y,          // The second vector 
        long long *incy);   // Stride in y vector (assume it is always 1)

