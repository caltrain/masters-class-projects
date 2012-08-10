
//-------------------------------------------------------------------------
// 
// Types of vectors to set up. The non-constant vectors are global ones, 
// not local. So for type linear with nprocs = 4 and n = 121, the first 
// values in the four local vectors would be 1, 31, 61, 91. Similarly 
// the first value for the alternating type would be 1 or -1, depending
// on the first index in the global vector that the local chunk defines.
//
// The example also shows that the code must work for the case where
// n is not evenly divisible by nprocs. Use a block distribution scheme
// where the last vector gets any extras from the remainder of n/nprocs.
// 
// Although the vector values are defined via a global scheme, at no
// time should any process have more than ceil(n/nprocs) parts of the
// global vector. That will be considered dead wrong. 
// 
//-------------------------------------------------------------------------

typedef enum {
    zero,       // a vector of all zeros
    ones,           // a vector of all ones
    alternating,    // a vector of alternating 1, -1
    linear,         // a vector with values going from 1 to n (not 0 to n-1)
    randomlocal,    // a vector with random values drawn from the interval [-1,1]
    othertype1,     // if you want to define more, add them here
    othertype2      // if you want to define more, add them here
} vectype;
