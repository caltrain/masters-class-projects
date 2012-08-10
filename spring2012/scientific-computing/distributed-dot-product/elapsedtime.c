//--------------------------------------------------------------------------------
// 
// Example timer for use from within C/C++. Five versions are selectable here,
// by (un)commenting out relevant parts delineated by "Version" comments below.
//
// Another Version needs to be added, one that calls MPI_Wtime.
//
// Note that this is actually a call to some system clock and multiple versions
// are provided via commenting/uncommenting out blocks below. The function
// gettimeofday() is on all systems, but generally a high resolution clock is a
// better choice if one is available. Read warnings in the comments about 
// nonstandard or nonportable usages.
//
// Also note the convention used here: a negative number is returned in case the 
// clock_gettime() call fails, instead of the error flag from that function.
//
//----------------
// Randall Bramley
// Department of Computer Science
// Indiana University, Bloomington
//----------------
// Started: Thu 26 Apr 2012, 01:42 PM
// Last Modified: Thu 26 Apr 2012, 06:09 PM
//--------------------------------------------------------------------------------

//-------------------------------------
// Version 1: using clock_gettime()
//-------------------------------------
// #include <time.h>
// 
// double elapsedtime(void)
// {
//     int flag;
//     clockid_t cid = CLOCK_REALTIME; // CLOCK_MONOTONE might be better
//     struct timespec tp;
//     double timing;
// 
//     flag = clock_gettime(cid, &tp);
//     if (flag == 0) 
//         timing = tp.tv_sec + 1.0e-9*tp.tv_nsec;
//     else 
//         timing = -17.0;  // If timer failed, return non-valid time
//     
//     return(timing);
// 
// };

//---------------------------------
// Version 2: using gettimeofday()
//---------------------------------
//  #include <time.h>
//#include <stddef.h>
//#include <sys/time.h>
//#include <unistd.h>                                                                  

//double elapsedtime()
//{
//    struct timeval t;
//    struct timezone whocares;
//    double total;
//    double sec, msec;     /* seconds */
//    double usec;          /* microseconds */

    // gettimeofday(&t, NULL);
//    gettimeofday(&t, &whocares);

//    msec = (double) (t.tv_sec);
//    usec = 1.0e-6*(double) (t.tv_usec);
//    total = msec + usec;
//    if (total < 0) 
//        return(-17.0);
//    else
//        return(total);

//}


//------------------------------------------------------------------------
// Version 3: using times(). This assumes that clktk = 100 ticks per 
// second. Returns a double that gives the sum of user and system time.
//------------------------------------------------------------------------
// #include <sys/times.h>
// 
// double elapsedtime(void)
// {
//   struct tms p;
//   times(&p);
//   return( (double) 0.01*(p.tms_utime + p.tms_stime) );
// }


//------------------------------------------------------------------------------
// Version 4: using a high resolution non-standard clock
// Beware: this hardcodes in the CPU Ghertz rate, which is specific to a single
// machine. On systems with the proc filesystem, rate can be obtained from 
//    cat /proc/cpuinfo
//------------------------------------------------------------------------------
// #include <stdio.h> 
// unsigned long long int cycles_x86_64(void)
// {
//   unsigned long long int val;
//   do {
//      unsigned int a, d;
//      asm volatile("rdtsc" : "=a" (a), "=d" (d));
//      (val) = ((long long)a) | (((long long)d)<<32);
//   } while(0);
//   return(val);
// }
// 
// double elapsedtime(void)
// {
//     unsigned long long int val;
//     double retval;
//     double cpurate = 3.2e9;
// 
//     val = cycles_x86_64();
//     retval = (double) val/ cpurate;
//     if (retval < 0.0)
//         return(-17.0);
//     else
//         return(retval);
// }

//-----------------------------------------
// Version 5: another HRC, not tested yet
//-----------------------------------------
// #define CPS 2327505000;
// static double iCPS;
// static unsigned start=0;
// 
// double second(void) /* Include an '_' if you will be calling from Fortan */
// {
//   double foo;
//   if (!start)
//   {
//      iCPS=1.0/(double)CPS;
//      start=1;
//   }
//   foo=iCPS*cycles_x86_64();
//   return(foo);
// }
//-------------------------------------------
//Version 6: Time calculation using MPI_Wtime
//-------------------------------------------
#include <mpi.h>

double elapsedtime(void)
{
	double retval = MPI_Wtime();
	if (retval < 0.0)
	{
         return(-17.0);
	}
	return retval;
}
