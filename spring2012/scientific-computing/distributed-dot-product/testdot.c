
#include <time.h> 
#include "globaldotproduct.c"
#include "setvec.c"
#include "elapsedtime.c"
#include <math.h>

int main(int argc, char **argv) 
{
	//num_procs. This variable matches with numprocsPointer. This denotes the total number of processes
	int num_procs = 0;     
	int ID = 0;
	long long i = 0ll;	
	double totalTime = 0.0;
	clock_t start, finish; 
	
	MPI_Status status;
	MPI_Init(&argc, &argv);
	MPI_Comm communicator = MPI_COMM_WORLD;
	MPI_Comm_rank(MPI_COMM_WORLD, &ID);
	MPI_Comm_size(MPI_COMM_WORLD, &num_procs);
	
	
	FILE *outputFilePointer; 
	FILE *sizesFilePointer; 
	
    double *A, *B;
	long long nflops = 0ll; 
	sizesFilePointer = fopen("sizes", "r"); 
	long long min_length, max_length, stride_length = 0ll; 
	long long vectorlength = 0ll;
	long long equalChunk = 0ll;
	long long chunksize = 0ll;

	double dotval = 0.0;	
	
	long long repetitionCount = 0ll;
	
	long long sizesFile[4];
	
	//Master reads the sizes file.
	if(ID==0)
	{
		if(!sizesFilePointer)
		{
			printf("Error: cant open the file.\n");
			MPI_Abort(communicator, 10);
			return 0;                   
		}
		fscanf(sizesFilePointer, "%lld %lld %lld %lld", &sizesFile[0], &sizesFile[1], &sizesFile[2], &sizesFile[3]);
		
		fclose(sizesFilePointer); 
	}
	
	// Broadcasting the sizes to all the processes
	MPI_Bcast(&sizesFile,4,MPI_LONG,0,MPI_COMM_WORLD);
	
	min_length =  sizesFile[0];
	max_length = sizesFile[1];
	stride_length = sizesFile[2];
	nflops = sizesFile[3];
	
	long long remaining = 0;// = max_length%num_procs;
	
	chunksize = max_length/(long long)num_procs;
	
	if(ID < (remaining))
	{
		chunksize++;
	}
	//Vector type is decided. 
	vectype aVecType = randomlocal;
	vectype bVecType = randomlocal;
	A = (double *)malloc((double)(chunksize) * sizeof(double));  
	B = (double *)malloc((double)(chunksize) * sizeof(double)); 
	
	for( vectorlength = min_length; vectorlength <= max_length; vectorlength += stride_length)
	{
		remaining = vectorlength%num_procs;
		long long chunksize = vectorlength/((long long)num_procs);
		if(ID <remaining)
		{
			chunksize++;// = max_length/(long long)num_procs + (1) ;
		}
		//printf("Chunk size in testdot %lld",chunksize);
		
		long long rankPointer = (long long)ID;
		long long numProcsPointer = (long long)num_procs;
		setvec(aVecType, &vectorlength, A, &rankPointer, &numProcsPointer);
		setvec(bVecType, &vectorlength, B, &rankPointer, &numProcsPointer);
		
		long long no_of_rep = nflops/(2*vectorlength);
		MPI_Barrier(communicator);
		start = elapsedtime(); 
		
		for(repetitionCount = 0; repetitionCount < no_of_rep; repetitionCount++)
		{
			dotval = 0.0;
			long long rankPointer = (long long)ID;
			long long numProcsPointer = (long long)num_procs;
			globaldotproduct(
				&chunksize, A, B,
				&dotval, &rankPointer, &numProcsPointer, &communicator);
		}
		
		// Waiting for all processes to finish computation
		MPI_Barrier(communicator);

		//calculating elapsed time
		finish = elapsedtime(); 
		totalTime = (double)(finish - start); 
		if(ID == 0)
		{
			double avg = (totalTime)/no_of_rep;
			outputFilePointer = fopen("results", "a+");
			fprintf(outputFilePointer, " %lld\t  %lld  \t %.17e \t%.17e \t %d \t %.17e \n", vectorlength, no_of_rep, totalTime, avg ,num_procs, dotval);
			fclose(outputFilePointer);  			   
		}
	}
	free(A);
	free(B);
	MPI_Finalize();
	return 1;
}
