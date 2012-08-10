#include <sys/time.h>
#include <stdio.h>

/********************************************************
Returns the difference between start and end time parameters.
*********************************************************/
double getDifference(struct timeval *start, struct timeval *end)
{
	return ((end->tv_sec * 1000000 + end->tv_usec) - (start->tv_sec * 1000000 + start->tv_usec));
}