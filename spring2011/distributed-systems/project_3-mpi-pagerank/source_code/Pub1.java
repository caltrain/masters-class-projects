package nbSample;

import java.util.Properties;
import java.util.Random;
import cgl.narada.event.NBEvent;
import cgl.narada.event.TemplateProfileAndSynopsisTypes;
import cgl.narada.service.client.ClientService;
import cgl.narada.service.client.EventProducer;
import cgl.narada.service.client.SessionService;
import org.hyperic.sigar.CpuPerc;
import org.hyperic.sigar.SigarException;
import org.hyperic.sigar.cmd.Shell;
import org.hyperic.sigar.cmd.SigarCommandBase;

class CpuInfo extends SigarCommandBase {
      public boolean displayTimes = true;
      static double cpucom;
      static double memcom;
      public CpuInfo(Shell shell) {
        super(shell);
      }

      public CpuInfo() {
        super();
      }

      public String getUsageShort() {
        return "Display cpu information";
      }

      public void output(CpuPerc cpu) throws SigarException {
        cpucom = cpu.getCombined()* 100;
        memcom = sigar.getMem().getUsedPercent();
      }

      public void output(String[] args) throws SigarException {
        org.hyperic.sigar.CpuInfo[] infos = this.sigar.getCpuInfoList();

        org.hyperic.sigar.CpuInfo info = infos[0];
        if ((info.getTotalCores() != info.getTotalSockets()) || (info.getCoresPerSocket() > info.getTotalCores())) {
        }

        if (!this.displayTimes) {
          return;
        }
        output(this.sigar.getCpuPerc());
      }
}
public class Pub1 extends CpuInfo{
    public static void main(String[] args) throws Exception {
        // message to be sent
        int i= 0;
       
        while(i<30)
        {
        new CpuInfo().processCommand(args);
        CpuInfo cp = new CpuInfo();
       
        String message = Double.toString(cp.cpucom)+ "," + Double.toString(cp.memcom)+",149.165.146.184";
       
        // initialize the connection properties
        int entityId = new Random().nextInt();
        ClientService clientService = SessionService.getClientService(entityId);
        Properties props = new Properties();
        props.put("hostname", Constants.BROKER_HOST);
        props.put("portnum", Constants.BROKER_PORT);

        clientService.initializeBrokerCommunications(props, "niotcp");

        // create event producer
        EventProducer producer = clientService.createEventProducer();
        producer.generateEventIdentifier(true);
        producer.setTemplateId(new Random().nextInt());
        producer.setDisableTimestamp(false);
       
        //publish event
        NBEvent nbEvent = producer.generateEvent(
                TemplateProfileAndSynopsisTypes.STRING, Constants.TOPIC, message.getBytes());
        producer.publishEvent(nbEvent);
        Thread.sleep(1000);
       
        //Closing connections
        clientService.closeBrokerConnection();
        clientService.terminateServices();
        i++;
        }
        System.exit(0);       
    }
}