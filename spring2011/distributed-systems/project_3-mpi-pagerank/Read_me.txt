Monitoring the CPU and memory utilization in local machine and euca
1)	Create a new project in Eclipse
2)	Before running the project , several jar files have to be imported for

	i)	Importing NaradaBroker library files.
	ii)	Importing JFreeChart library files
	iii)	Importing Sigar files
	
3)	The NaradaBroker library files are included in NaradaBrokering.jar, jug-uuid.jar while JFreechart library files are included in jfreechart-1.0.13-demo.jar,jfreechart-1.0.13.jar, jfreechart-1.0.13-swt.jar and sigar library files are included in sigar.jar.
4)	Set BROKER_HOST and BROKER_PORT in Constants.java.
5)	Compile Render.java
6)	Run the ConsumerClient.java first which includes the JFreechart that plots a graph for the values acquired from the daemon running in Pub1.java .
7)	Run Pub1.java
8)	The message is customized with CPU and memory utilization values calculated using Sigar API in Pub1.java.