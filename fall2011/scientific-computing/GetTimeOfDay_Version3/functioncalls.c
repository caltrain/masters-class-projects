#include "lonely.c"
#include "elapsedtime.c"
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#define NUMBER_OF_CALLS 1000000

FILE *fp;

/*********************************************/
/*
performLoop() function calls a range of functions starting
from funtion00() upto funtion25() and records the average value
of time it took to call each function(each function is called multiple times).
The average time values are written on a text file in two rows.
*/
/*********************************************/
void performLoop()
{
	FILE *callResults = fopen("fcall_results.txt", "w");
	char buffer[30];
	struct timeval start, end;
	int i = 0;
	double difference = 0.0;
	double total = 0;
	double average = 0;
	int the_number_of_arguments =0;

	/*
	This Segment calls and records the average time taken by function00().
	function00 has no arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{

		function00();

	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);

	printf("Calling function00() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 0;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function01().
		function01 has 1 argument.
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{

		function01(3.2);

	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function01() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 1;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);


	/*
		This Segment calls and records the average time taken by function02().
		function02 has 2 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function02(3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function02() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 2;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);


	/*
		This Segment calls and records the average time taken by function03().
		function03 has 3 arguments.
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function03(3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function03() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 3;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);


	/*
		This Segment calls and records the average time taken by function04().
		function04 has 4 arguments
	*/
	total=0;average=0;difference=0.0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function04(3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function04() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 4;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function05().
		function05 has 5 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function05(3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function05() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 5;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function06().
		function06 has 6 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function06(3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function06() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 6;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function07().
		function07 has 7 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function07(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function07() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 7;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function08().
		function08 has 8 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function08(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function08() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 8;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function09().
		function09 has 9 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function09(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function09() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 9;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function10().
		function10 has 10 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function10(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function10() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 10;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function11().
		function11 has 11 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
		function11(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function11() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 11;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function12().
		function12 has 12 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
	function12(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function12() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 12;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	/*
		This Segment calls and records the average time taken by function15().
		function15 has 15 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
	function15(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function15() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 15;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);


	/*
		This Segment calls and records the average time taken by function25().
		function25 has 25 arguments
	*/
	total=0;average=0;
	gettimeofday(&start, NULL);
	for(i=0; i<NUMBER_OF_CALLS ; i++)
	{
	function25(3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2, 3.2);
	}
	gettimeofday(&end, NULL);
	difference = getDifference(&start, &end);
	printf("Calling function25() ");
	average = difference / (double)NUMBER_OF_CALLS;
	printf("Average: %f \n", average);
	the_number_of_arguments = 25;
	fprintf(callResults, "%d %f\n", the_number_of_arguments , average);

	fclose(fp);
}

void main()
{
	if (fp = fopen("fcall_results.txt", "w"))
	{
		fclose(fp);
		performLoop();
	}
	else
		printf("Error opening fcall_results.txt \n");
}