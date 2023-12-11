package com.example.demo;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
//default gateway
import java.net.HttpURLConnection;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
//3. PING
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;

//DHCP
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
//4. Tracert
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc791Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.SimpleBuilder;
import org.pcap4j.packet.UnknownPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IcmpV4Type;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//

//7. Nslookup
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import oshi.SystemInfo;
import oshi.hardware.NetworkIF;

@SpringBootApplication
public class DemoApplication {

	public static void main(String[] args) {

		// System.out.println(getIPv4Address());
		// System.out.println(getSubnetMask());
		// System.out.println(getPhysicalAddress());

		// try {
		// 	System.out.println("WAN IP Address: " + getWANIP());

		// } catch (Exception e) {
		// 	e.printStackTrace();
		// }

		// ping();

		// performNsLookup("google.com");
		// traceroute("8.8.8.8");

		// System.out.println(getWebPageLoadTime("http://facebook.com"));

		// scanPorts("facebook.com", 200, 70, 90, "scan_results.txt");

		// WifiInfo();
		// System.out.println(doTcpPing());

	}

	// #region 1. IPCONFIG (done)

	public static String getIPv4Address() {
		try {
			InetAddress localHost = InetAddress.getLocalHost();
			if (localHost != null && localHost.getHostAddress().indexOf(":") == -1) {
				return localHost.getHostAddress();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return "unknown";

	}

	public static String getSubnetMask() {
		try {
			Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
			while (networkInterfaces.hasMoreElements()) {
				NetworkInterface networkInterface = networkInterfaces.nextElement();
				for (InterfaceAddress interfaceAddress : networkInterface.getInterfaceAddresses()) {
					InetAddress inetAddress = interfaceAddress.getAddress();
					if (!inetAddress.isLoopbackAddress() && inetAddress.getHostAddress().indexOf(":") == -1) {
						short subnetPrefixLength = interfaceAddress.getNetworkPrefixLength();
						return calculateSubnetMask(subnetPrefixLength);
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace(); // Handle the exception properly in your application
		}

		return "Unknown";
	}

	private static String calculateSubnetMask(short subnetPrefixLength) {
		int subnetMask = 0xFFFFFFFF << (32 - subnetPrefixLength);
		return String.format("%d.%d.%d.%d",
				(subnetMask >> 24) & 255,
				(subnetMask >> 16) & 255,
				(subnetMask >> 8) & 255,
				subnetMask & 255);
	}

	public static String getPhysicalAddress() {
		try {
			Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
			while (networkInterfaces.hasMoreElements()) {
				NetworkInterface networkInterface = networkInterfaces.nextElement();
				byte[] mac = networkInterface.getHardwareAddress();
				if (mac != null && mac.length == 6) {
					StringBuilder macAddress = new StringBuilder();
					for (int i = 0; i < mac.length; i++) {
						macAddress.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
					}
					return macAddress.toString();
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return "Unknown";
	}

	// default gateway

	// #endregion
	
	// #region 2. WAN IP & MAC modem (done)

	public static String getWANIP() throws IOException {
		URL url = new URL("https://checkip.amazonaws.com/");
		HttpsURLConnection con = (HttpsURLConnection) url.openConnection();
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
			return reader.readLine().trim();
		}
	}

	// #endregion
	
	// #region 3. PING (done)

	private static void ping() {
		try {
			String targetIP = "216.58.200.238";
			int ttl = 59; // Time-to-Live (TTL) value
			int timeout = 10000; // Timeout in milliseconds
			int packetSize = 32; // Packet size in bytes

			for (int i = 0; i < 3; i++) {
				PingResult result = sendPing(targetIP, ttl, timeout, packetSize);
				System.out.println("Ping #" + (i + 1) + " - IP: " + result.ipAddress +
						" Reply: " + result.replyStatus +
						" Bytes: " + result.bytesSent +
						" Time: " + result.responseTime + " ms" +
						" TTL: " + result.ttl);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static PingResult sendPing(String ipAddress, int ttl, int timeout, int packetSize) throws IOException {
		InetAddress address = InetAddress.getByName(ipAddress);

		// Set the Time-to-Live (TTL) value in NetworkInterface (netif)
		NetworkInterface netif = null; // You can specify the desired network interface here

		// Send the ping request with TTL and timeout
		long startTime = System.currentTimeMillis();
		boolean reachable = address.isReachable(netif, ttl, timeout);
		long endTime = System.currentTimeMillis();
		long responseTime = endTime - startTime;

		// Create a PingResult object to store the results
		PingResult result = new PingResult();
		result.ipAddress = address.getHostAddress();
		result.replyStatus = reachable ? "Success" : "Timeout";
		result.bytesSent = packetSize;
		result.responseTime = responseTime;
		result.ttl = ttl;

		return result;
	}

	private static class PingResult {
		String ipAddress;
		String replyStatus;
		int bytesSent;
		long responseTime;
		int ttl;
	}

	// #endregion

	// #region 4. TRACERT (not yet)

	// The code provided sets up the basic mechanism for sending out packets with
	// increasing TTL values.
	// However, to complete the traceroute functionality, you need to capture and
	// analyze the ICMP Time Exceeded messages returned by the intermediate routers.

	// This requires:

	// Setting up a packet listener to capture incoming ICMP messages.
	// Extracting the source IP address from these messages to identify the hops.
	// Matching these incoming messages with the outgoing packets to correctly map
	// the route.

	public static void traceroute(String ipAddress) {
		try {
			InetAddress addr = InetAddress.getByName(ipAddress);
			PcapNetworkInterface nif = new NifSelector().selectNetworkInterface();

			if (nif == null) {
				return;
			}
			// Convert LinkLayerAddress to MacAddress
			MacAddress srcMacAddress;
			if (!nif.getLinkLayerAddresses().isEmpty() && nif.getLinkLayerAddresses().get(0) instanceof MacAddress) {
				srcMacAddress = (MacAddress) nif.getLinkLayerAddresses().get(0);
			} else {
				System.out.println("No MAC address available for the selected interface");
				return;
			}
			int snapLen = 65536;
			int timeout = 50;
			Thread listenerThread = new Thread(() -> {
				try (PcapHandle receiveHandle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
						timeout)) {
					receiveHandle.loop(-1, new PacketListener() {
						@Override
						public void gotPacket(Packet packet) {
							if (packet.contains(IcmpV4CommonPacket.class)) {
								IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
								if (icmpPacket.getHeader().getType() == IcmpV4Type.ECHO_REPLY) {
									// Extract info from the echo reply
									Date receiveTime = new Date();
									int receivedTtl = packet.get(IpV4Packet.class).getHeader().getTtl();
									InetAddress sourceIp = packet.get(IpV4Packet.class).getHeader().getSrcAddr();

									// Displaying the information
									System.out.println("Reply from " + sourceIp.getHostAddress() +
											": bytes=32 time=" + receiveTime.getTime() + "ms TTL=" + receivedTtl);
								}
							}
						}
					});
				} catch (PcapNativeException | InterruptedException | NotOpenException e) {
					e.printStackTrace();
				}
			});
			listenerThread.start();
			try (PcapHandle sendHandle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
					timeout)) {
				for (int ttl = 1; ttl <= 30; ttl++) {
					IcmpV4EchoPacket icmpV4EchoPacket = new IcmpV4EchoPacket.Builder()
							.identifier((short) 0)
							.sequenceNumber((short) ttl)
							.payloadBuilder(new UnknownPacket.Builder().rawData(new byte[32]))
							.build();

					IpV4Packet ipV4Packet = new IpV4Packet.Builder()
							.version(IpVersion.IPV4)
							.tos(IpV4Rfc791Tos.newInstance((byte) 0))
							.ttl((byte) ttl)
							.protocol(IpNumber.ICMPV4)
							.srcAddr((Inet4Address) InetAddress.getLocalHost())
							.dstAddr((Inet4Address) addr)
							.payloadBuilder(new SimpleBuilder(icmpV4EchoPacket))
							.correctChecksumAtBuild(true)
							.correctLengthAtBuild(true)
							.build();

					EthernetPacket ethernetPacket = new EthernetPacket.Builder()
							.srcAddr(srcMacAddress)
							.dstAddr(MacAddress.ETHER_BROADCAST_ADDRESS)
							.type(EtherType.IPV4)
							.payloadBuilder(new SimpleBuilder(ipV4Packet))
							.paddingAtBuild(true)
							.build();

					sendHandle.sendPacket(ethernetPacket.getRawData());
					System.out.println("Sent packet with TTL: " + ttl);
					// Additional code to wait for a short period after sending each packet
					// to allow time for a response
					try {
						Thread.sleep(1000); // wait for 1 second for a response
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
					}
				}
			}
			// Ensure the listener thread also stops after all packets are sent
			listenerThread.interrupt();

		} catch (PcapNativeException | IllegalArgumentException | IllegalStateException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// #endregion

	// #region 5. TCPping (done)

	public static String doTcpPing() {
		String result = "";
		int numPackets = 5;
		for (int i = 0; i < numPackets; i++) {
			long startTime = System.currentTimeMillis();
			// long startTime = System.nanoTime();

			boolean isReachable = tcpPing("facebook.com", 80);

			long endTime = System.currentTimeMillis();
			// long endTime = System.nanoTime();

			if (isReachable) {
				long roundTripTime = endTime - startTime;
				// long roundTripTime = (endTime - startTime)/ 1000000;

				System.out.println("Port is open. Time: " + roundTripTime + "ms");
			} else {
				System.out.println("Port is not reachable.");
			}
		}
		return result;
	}

	public static boolean tcpPing(String host, int port) {
		try (Socket socket = new Socket()) {
			// Set a timeout for the socket connection
			socket.connect(new InetSocketAddress(host, port), 5000); // 5-second timeout
			return true;
		} catch (SocketTimeoutException e) {
			// Connection timed out
			return false;
		} catch (IOException e) {
			// Other IO errors (e.g., host not found, connection refused)
			return false;
		}
	}

	// #endregion

	// #region 6. TraceTCP (not yet)
	// #endregion

	// #region 7. Nslookup (done)

	public static void performNsLookup(String host) {
		try {
			// Lookup records
			Lookup lookup = new Lookup(host, Type.ANY);
			Record[] records = lookup.run();

			// Check the result and print appropriate message
			if (lookup.getResult() == Lookup.SUCCESSFUL) {
				System.out.println("Records for " + host + ":");
				for (Record record : records) {
					System.out.println(record);
				}
			} else {
				System.out.println("Error occurred: " + lookup.getErrorString());
			}

			// Additional information (Name servers, Address, etc.)
			// System.out.println("Additional information:");
			// System.out.println("Resolver: " + lookup.getDefaultResolver());
			// Additional information (Aliases)
			// Name[] aliases = lookup.getAliases();
			// if (aliases != null && aliases.length > 0) {
			// List<String> aliasStrings = new ArrayList<>();
			// for (Name alias : aliases) {
			// aliasStrings.add(alias.toString());
			// }
			// System.out.println("Aliases: " + String.join(", ", aliasStrings));
			// } else {
			// System.out.println("No aliases found.");
			// }

		} catch (TextParseException e) {
			System.err.println("Invalid DNS lookup request: " + e.getMessage());
		}
	}

	// #endregion

	// #region 8. Page load (done)

	public static String getWebPageLoadTime(String hostname) {
		String result = "";
		long startTime = System.currentTimeMillis();

		try {
			URL url = new URL(hostname);
			HttpURLConnection connection = (HttpURLConnection) url.openConnection();
			connection.connect();
			connection.disconnect();
			long endTime = System.currentTimeMillis();
			Long loadTime = endTime - startTime;
			result = "Time to load " + hostname + ": " + loadTime + " milliseconds";
			return result;
		} catch (IOException e) {
			e.printStackTrace();
			result = "Failed to load " + hostname;
			return result;
		}

	}

	// #endregion

	// #region 9. Port check (done)

	private static void scanPorts(String host, int timeout, int startPort, int endPort, String resultFileName) {
		try (FileWriter fileWriter = new FileWriter(resultFileName)) {
			for (int port = startPort; port <= endPort; port++) {
				String status = checkPort(host, port, timeout);
				fileWriter.write("Port " + port + ": " + status + "\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static String checkPort(String host, int port, int timeout) {
		try (Socket socket = new Socket()) {
			socket.connect(new InetSocketAddress(host, port), timeout);
			return "Open";
		} catch (UnknownHostException e) {
			return "Unknown Host";
		} catch (SocketTimeoutException e) {
			return "Timeout";
		} catch (IOException e) {
			String message = e.getMessage();
			if (message.contains("Connection refused")) {
				return "Refused";
			} else if (message.contains("No route to host")) {
				return "Filtered";
			} else {
				return "Closed";
			}
		}
	}

	// #endregion

	// #region 10 & 11. Download and Upload rate (done)

	public static void WifiInfo() {
		SystemInfo systemInfo = new SystemInfo();
		List<NetworkIF> networkIFs = systemInfo.getHardware().getNetworkIFs();

		for (NetworkIF networkInterface : networkIFs) {
			if (networkInterface.getBytesRecv() > 0) {
				System.out.println("Interface Name: " + networkInterface.getDisplayName());
				System.out.println("Signal Strength: " + networkInterface.getSpeed());
				System.out.println("Channel Width: " + networkInterface.getMTU());

				// IPv4 Addresses (Security Type)
				System.out.println("Security Type (IPv4):");
				for (String ipv4Address : networkInterface.getIPv4addr()) {
					System.out.println("  " + ipv4Address);
				}

				// IPv6 Addresses (Encryption Type)
				System.out.println("Encryption Type (IPv6):");
				for (String ipv6Address : networkInterface.getIPv6addr()) {
					System.out.println("  " + ipv6Address);
				}

				System.out.println("Download Rate: " + networkInterface.getBytesRecv() / 1024 / 1024 + " Mbps");
				System.out.println("Upload Rate: " + networkInterface.getBytesSent() / 1024 / 1024 + " Mbps");
				System.out.println("- - - - - - - - - - - - - - - - - - - - - - - - ");
			}
		}
	}

	// #endregion

	// #region 12. Wifi signal strength (not yet)

	// #endregion

	// #region 13. DHCP packets capture (not yet)

	// public static void captureDHCP() {
	// String networkInterfaceName = "eth0"; // Change to your network interface
	// name
	// String outputFileName = "dhcp_offer.txt";

	// PcapNetworkInterface device = getNetworkDevice(networkInterfaceName);
	// if (device == null) {
	// System.out.println("Network device not found.");
	// return;
	// }

	// // Prepare DHCP Discover Packet
	// DhcpV4Packet dhcpDiscoverPacket = buildDhcpDiscoverPacket(device);

	// try (PcapHandle handle = device.openLive(65536,
	// PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
	// PcapHandle sendHandle = device.openLive(65536,
	// PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, 0)) {

	// // Send DHCP Discover Packet
	// sendHandle.sendPacket(dhcpDiscoverPacket);

	// // Capture DHCP Offer Packet
	// PacketListener listener = packet -> {
	// if (packet.contains(DhcpV4Packet.class)) {
	// DhcpV4Packet dhcpPacket = packet.get(DhcpV4Packet.class);
	// // Write packet details to file
	// try (FileWriter writer = new FileWriter(outputFileName, true)) {
	// writer.write("Source MAC: " + packet.getHeader().getSrcAddr() + "\n");
	// writer.write("Destination MAC: " + packet.getHeader().getDstAddr() + "\n");
	// writer.write("DHCP Message Type: " + dhcpPacket.getHeader().getMessageType()
	// + "\n");
	// // Add other DHCP information you want to log
	// } catch (IOException e) {
	// e.printStackTrace();
	// }
	// }
	// };

	// handle.loop(10, listener);

	// } catch (PcapNativeException | NotOpenException | PcapPacketException |
	// InterruptedException e) {
	// e.printStackTrace();
	// }
	// }

	// private static PcapNetworkInterface getNetworkDevice(String name) {
	// try {
	// return Pcaps.getDevByName(name);
	// } catch (PcapNativeException e) {
	// e.printStackTrace();
	// return null;
	// }
	// }

	// private static DhcpV4Packet buildDhcpDiscoverPacket(PcapNetworkInterface
	// device) {
	// // Implement DHCP Discover packet construction
	// // This includes setting up Ethernet, IP, UDP headers, and DHCP specific
	// fields
	// // Return the constructed DhcpV4Packet
	// return null;
	// }

	// #endregion

	// #region 14. SNR (not yet)
	// #endregion
}