package burp;

import java.util.ArrayList;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;


public class BurpExtender implements IBurpExtender, ITab, ActionListener
{
	private IBurpExtenderCallbacks callbacks;
	private JPanel panel;    
	private JTextField fileNameTextField;

	private final static String ExtensionName = "Nessus Loader";

	@Override
	public Component getUiComponent()
	{
		return panel;
	}

	@Override
	public String getTabCaption()
	{
		return ExtensionName;
	}

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks myCallbacks)
	{
		callbacks = myCallbacks;
		callbacks.setExtensionName(ExtensionName);

		SwingUtilities.invokeLater(new Runnable() 
		{
			@Override
			public void run()
			{
				panel = new JPanel();
				JLabel fileNameLabel = new JLabel("File (*.nessus):");
				JButton browseButton = new JButton("Browse...");
				browseButton.setActionCommand("browse");
				browseButton.addActionListener(BurpExtender.this);
				fileNameTextField = new JTextField(50);
				JButton runButton = new JButton("Parse file and add targets to site map");
				runButton.setActionCommand("run");
				runButton.addActionListener(BurpExtender.this);

				panel.add(fileNameLabel);
				panel.add(browseButton);
				panel.add(fileNameTextField);
				panel.add(runButton);

				callbacks.customizeUiComponent(fileNameLabel);
				callbacks.customizeUiComponent(browseButton);
				callbacks.customizeUiComponent(fileNameTextField);
				callbacks.customizeUiComponent(runButton);

				callbacks.addSuiteTab(BurpExtender.this);
			}
		});  
	}


	public void actionPerformed(ActionEvent ev) {
		if (ev.getActionCommand().equals("browse")) {
			JFileChooser fileChooser = new JFileChooser();
			if (fileChooser.showOpenDialog(null) == JFileChooser.APPROVE_OPTION)
				fileNameTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
		} else if (ev.getActionCommand().equals("run")) {
			try {
				ArrayList<URL> urls;

				File inputFile = new File(fileNameTextField.getText());
				if (!inputFile.exists())
				{
				    throw new Exception("File not found: " + fileNameTextField.getText());
				}

				DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
				DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
				Document doc;

				try {
					doc = dBuilder.parse(inputFile);
					doc.getDocumentElement().normalize();
				} catch (Exception pe) {
					throw new Exception("Error parsing file: " + pe.getMessage());
				}

				urls = getWebURLs(doc);

				// put this in a new thread since it does http(s) requests and we don't want to block the UI
				Thread thread = new Thread(new Runnable() { public void run() {
					addURLsToSiteMap(urls);
				}});
				// don't prevent the JVM from exiting when the program finishes but the thread is still running
				thread.setDaemon(true);
				// kick it off
				thread.start();
				
				JOptionPane.showMessageDialog(null, "Found " + urls.size() + " targets in .nessus file, adding to site map (under Target tab)...", "Adding...", JOptionPane.INFORMATION_MESSAGE);

			} catch (Exception e) {
				JOptionPane.showMessageDialog(null, e.getMessage(), "Nope", JOptionPane.ERROR_MESSAGE);
				callbacks.printError(e.getMessage());
			}
		}
	}

	private void addURLsToSiteMap(ArrayList<URL> urls)
	{
		try {
			urls.forEach((url) -> {
				callbacks.printOutput("Adding " + url + " to site map...");
				IHttpService httpService = callbacks.getHelpers().buildHttpService(url.getHost(), url.getPort(), url.getProtocol());
				byte[] request = callbacks.getHelpers().buildHttpRequest(url);
				IHttpRequestResponse requestResponse = callbacks.makeHttpRequest(httpService, request);
				callbacks.addToSiteMap(requestResponse);
			});

			callbacks.printOutput("Done! Added " + urls.size() + " targets to site map.");

		} catch (Exception e) {
			callbacks.printError(e.getMessage());
		}
	}

	private ArrayList<URL> getWebURLs(Document nessus) throws MalformedURLException
	{
		ArrayList<URL> urls = new ArrayList<URL>();

		NodeList reportHosts = nessus.getElementsByTagName("ReportHost");

		for (int i = 0; i < reportHosts.getLength(); i++)
		{
			Element reportHostElement = (Element)reportHosts.item(i);
			String host = reportHostElement.getAttribute("name");

			NodeList reportItems = reportHostElement.getElementsByTagName("ReportItem");
			for (int j = 0; j < reportItems.getLength(); j++)
			{
				Element reportItemElement = (Element)reportItems.item(j);
				int pluginID = Integer.parseInt(reportItemElement.getAttribute("pluginID"));
				String svc_name = reportItemElement.getAttribute("svc_name");

				// Service Detection https://www.tenable.com/plugins/nessus/22964
				if (pluginID == 22964 && svc_name.equals("www"))
				{
					String output = reportItemElement.getElementsByTagName("plugin_output").item(0).getTextContent();
					if (output.startsWith("A web server is running on this port"))
					{
						String protocol = "http";
						if (output.contains("through"))
							protocol += "s";
						int port = Integer.parseInt(reportItemElement.getAttribute("port"));
						urls.add(new URL(protocol, host, port, "/"));
					}
				}
			}
		}

		return urls;
	}
}

