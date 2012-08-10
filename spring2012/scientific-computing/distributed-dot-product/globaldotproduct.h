//-------------------------------------------------------------------------------------
//
// Compute the global dotproduct of vectors x and y, where the local process
// owns the parts stored in the arrays localx and localy. Both are of length
// localn, which may vary from one process to another.  The communicator group
// is dotcomm. As explained in class, all of the input scalar variables are
// passed as addresses, not by value, so that the function can be called from
// any language interoperable with C. In particular, this returns void, not the
// dotproduct value.
// 
// This function should call the local dotproduct function ddot for computing the
// part of the dotproduct that is locally owned, then use allgather to sum up the
// nprocs pieces.
// 
//----------------
// Other notes: 
//----------------
//
// Having to dereference scalars each time they are used is a pain and unnatural
// in C. I find it easier to simply declare a local variable initialized by the 
// pointee, e.g. "int locallength = *localn;" rather than always dereferencing.
// Since that is only an issue for scalars (versus arrays), it is a reasonable
// amount of extra storage to incur.
//
// Be sure to check locally for the value pointed at by localn to be a valid length
//    
//-------------------------------------------------------------------------------------

void globaldotproduct(
        long long *localn,        // length of local vector segments
        double *localx,           // local segment of vector x
        double *localy,           // local segment of vector y
        double *dotval,           // the value of the dotproduct of the full global x and y
        long long *localrank,     // rank of local process, in range 0 to nprocs-1
        long long *nprocs,        // total number of processes in dotcomm
        MPI_Comm *dotcomm         // pointer to mpi communicator
        );
