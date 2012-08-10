package nbSample;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;

import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.CombinedDomainXYPlot;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.StandardXYItemRenderer;
import org.jfree.data.time.Millisecond;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;
import org.jfree.ui.ApplicationFrame;
import org.jfree.ui.RefineryUtilities;

  public class Render extends ApplicationFrame implements ActionListener {
      /** The number of subplots. */
      public static final int SUBPLOT_COUNT = 2;
      
      /** The datasets. */
      private TimeSeriesCollection[] datasets;
      /** The most recent value added to series 1. */
      private double[] lastValue = new double[SUBPLOT_COUNT];

      /**
       * Constructs a new demonstration application.
       *
       * @param title  the frame title.
       */
      public Render(final String title) {

          super(title);
          
          final CombinedDomainXYPlot plot = new CombinedDomainXYPlot(new DateAxis("Time"));
          this.datasets = new TimeSeriesCollection[SUBPLOT_COUNT];
          //Y axis plot
          {
              this.lastValue[0] = 100.0;
              final TimeSeries series = new TimeSeries("CPU", Millisecond.class);
              this.datasets[0] = new TimeSeriesCollection(series);
              final NumberAxis rangeAxis = new NumberAxis("CPU Utilization");
              rangeAxis.setAutoRangeIncludesZero(false);
              final XYPlot subplot = new XYPlot(
                      this.datasets[0], null, rangeAxis, new StandardXYItemRenderer()
              );
              subplot.setBackgroundPaint(Color.lightGray);
              subplot.setDomainGridlinePaint(Color.white);
              subplot.setRangeGridlinePaint(Color.white);
              plot.add(subplot);
          }
          {
              this.lastValue[1] = 100.0;
              final TimeSeries series = new TimeSeries("Memory", Millisecond.class);
              this.datasets[1] = new TimeSeriesCollection(series);
              final NumberAxis rangeAxis = new NumberAxis("Memory Utilization");
              rangeAxis.setAutoRangeIncludesZero(false);
              final XYPlot subplot = new XYPlot(
                      this.datasets[1], null, rangeAxis, new StandardXYItemRenderer()
              );
              subplot.setBackgroundPaint(Color.lightGray);
              subplot.setDomainGridlinePaint(Color.white);
              subplot.setRangeGridlinePaint(Color.white);
              plot.add(subplot);
          }
          //End of Y axis plot

          final JFreeChart chart = new JFreeChart("Performance Index", plot);
  //chart.getLegend().setAnchor(Legend.EAST);
          chart.setBorderPaint(Color.black);
          chart.setBorderVisible(true);
          chart.setBackgroundPaint(Color.white);
          
          plot.setBackgroundPaint(Color.lightGray);
          plot.setDomainGridlinePaint(Color.white);
          plot.setRangeGridlinePaint(Color.white);
    //      plot.setAxisOffset(new Spacer(Spacer.ABSOLUTE, 4, 4, 4, 4));
          final ValueAxis axis = plot.getDomainAxis();
          axis.setAutoRange(true);
          axis.setFixedAutoRange(60000.0);  // 60 seconds
          
          final JPanel content = new JPanel(new BorderLayout());

          final ChartPanel chartPanel = new ChartPanel(chart);
          content.add(chartPanel);

          final JPanel buttonPanel = new JPanel(new FlowLayout());
          
          content.add(buttonPanel, BorderLayout.SOUTH);
          chartPanel.setPreferredSize(new java.awt.Dimension(500, 470));
          chartPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
          setContentPane(content);

      }
      
      public void actionPerformed(final ActionEvent e)
      {
          if (e.getActionCommand().equals("ADD_ALL")) {
              final Millisecond now = new Millisecond();
              for (int i = 0; i < SUBPLOT_COUNT; i++) {
                  this.lastValue[i] = this.lastValue[i] * (0.90 + 0.2 * Math.random());
                  this.datasets[i].getSeries(0).add(new Millisecond(), this.lastValue[i]);       
              }
          }
      }
      public void performance_plot(double cpu_util, double mem_used)
      {
    	  this.datasets[0].getSeries(0).add(new Millisecond(), cpu_util);
    	  this.datasets[1].getSeries(0).add(new Millisecond(), mem_used);
      }
}
