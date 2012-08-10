package nbSample;
import java.util.Properties;
import java.util.Random;

import org.jfree.ui.RefineryUtilities;

import cgl.narada.event.NBEvent;
import cgl.narada.event.TemplateProfileAndSynopsisTypes;
import cgl.narada.matching.Profile;
import cgl.narada.service.client.ClientService;
import cgl.narada.service.client.EventConsumer;
import cgl.narada.service.client.NBEventListener;
import cgl.narada.service.client.SessionService;

public class ConsumerClient implements  NBEventListener  {
    static Render demo = new Render("Performance index");
	static String cpu_perf, mem_util;
	String combined_perf;
	String[] perf_array = new String[2];
	public static String TCP_COMM_TYPE = "niotcp";

	public void onEvent(NBEvent message) {
		
		System.out.println("Received Event {" + message.getContentSynopsis() + "} "
	            + new String(message.getContentPayload()));
		combined_perf = new String(message.getContentPayload()).toString();
		perf_array = combined_perf.split(",");
		cpu_perf = perf_array[0];
		mem_util = perf_array[1];
		System.out.println("Cpu Performance: " + cpu_perf +"\nMemory Utilization: "+mem_util);
		//custom_render(Double.parseDouble(cpu_perf), Double.parseDouble(mem_util));
		demo.performance_plot(Double.parseDouble(cpu_perf), Double.parseDouble(mem_util)); 
	}
	
	public static void main(String[] args) throws Exception {
	      demo.pack();
	      RefineryUtilities.centerFrameOnScreen(demo);
	      demo.setVisible(true);
		// initialize the connection properties
		int entityId = new Random().nextInt();
		ClientService clientService = SessionService.getClientService(entityId);
		Properties props = new Properties();
		props.put("hostname", Constants.BROKER_HOST);
		props.put("portnum", Constants.BROKER_PORT);
		
		clientService.initializeBrokerCommunications(props, TCP_COMM_TYPE);
		
		// create consumer
		EventConsumer  consumer = clientService.createEventConsumer(new ConsumerClient());
		
		//subscribe to the topic
		Profile profile = clientService.createProfile(
				TemplateProfileAndSynopsisTypes.STRING, Constants.TOPIC);
		consumer.subscribeTo(profile);
	}
}
