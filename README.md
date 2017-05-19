# User Driven Troubleshooting Architecture for Software-Defined Networking
This PoC code is for an envisioned architecture discussed in a research paper.

## Requirements:
 - python 
 - scapy (for manually crafting specific packets for experiments)
 - Mininet environment
 - Ryu controller
 - curl for interacting with the controller
 
## Quick Walkthrough:
 The Proof-of-Concept of the architecture is written in a way to demonstrate its process step by step by providing a REST API a user can use for following the operation.
###### First, download the source into ryu/ryu/app/ directory:
```
$ cd $HOME/ryu/ryu/app/
$ git clone https://github.com/cslev/nmaas
```
This will create an nmaas directory under ryu/ryu/app.
In the directory, you will find several python files, however only two of them are worth noting here, which are __nmaas_network.py__ (for firing up a mininet topology with hosts and switches) and __nmaas_network_controller.py__ (the SDN controller).  


###### nmaas_network_controller.py
The controller implements numerous low-level features such as topology discovery via LLDP, including host discovery through their first packets (automatically sent when the topology is up), building a network graph from the topology to calculate shortest paths, etc.
For the easiest and smoothest operation, therefore it is recommended to start the controller first:
```
$ cd $HOME/ryu
$ sudo PYTHONPATH=. ./bin/ryu-manager --observe-links ryu/app/nmaas/nmaas_network_controller.py
```
After this, the controller is up and running and instantiated the REST API module as well (localhost:8080). Through this API will you be able to manage the controller and observe its operation step by step.
Issuing the following command will gives you the possible REST API calls handled by the controller:
```
curl localhost:8080/
```
Each call being under __/topology__ is related to the basic operation of a standard SDN controller, e.g., getting topology information to follow what's happening under the hood, forcing the controller to update the topology information, printing out shortest paths, installing shortest paths)


###### nmaas_network.py
Before getting into details, initiate the topology as well:
```
$ cd $HOME/ryu/ryu/app/nmaas
$ sudo mn --clean; sudo python nmaas_network.py;
```
For demonstrational purposes, the links are set to have different delays by default.

After this mininet fires up the following topology, where the numbers on the links shows the port identifiers, and each link's cost is 1:
![topology](https://cloud.githubusercontent.com/assets/8448436/25897428/d6d7a84c-357f-11e7-8459-7186db73aa81.png)
One can observe from the output of the controller that it finds the switches and hosts and they are added to the network graph.

To assure you about this, simply call
```
$ curl localhost:8080/topology/graph
```
This will give you all the related topology info (links, ports, etc.). It is only for debugging reasons, so you don't have to get through them (for now).
Currently, switches do not have any meaningful forwarding rules, so issue the following command:
```
$ curl localhost:8080/topology/install_shortest_paths
```
As the URL suggests, this will ask the controller to install Layer-3 level forwarding rules (i.e., destination IP based routing) based on the shortest paths. Since there are several shortest paths between many of the nodes, ECMP rules are being installed meaning that you are not able to predict a specific packet's fate, i.e., be aware of in advance which path that packet will take.

For instance, consider the case of H1 and H7. The path from H1 can be S1-S3-S5-H7, or S1-S2-S5-H7. 
Note that you can get this information from the controller for any node-pairs at any time by issuing the following command:
```
$ curl localhost:8080/topology/shortest_paths
```
In case of H1 and H7, look for the lines 
```
...
h1 -> h7:
0: h1->s1->s3->s5->h7
1: h1->s1->s2->s5->h7
...
```

## Path tracing 
Now, we turn to the path tracing EDT provides. Obviously, when a problem occurs, such as an application's traffic suffers latency, the prompt identification of the traversed path is crucial. Here, we assume that the latency of a specific application's traffic increased, and we want to investigate its root cause, however first we need to identify the involved elements.

In order to capture a specific application's traffic, EDT temporarily tags the corresponging production traffic, captures it by the carefully crafted flow rules, and traces the taken path accordingly.
Let us see this in operation: capture a specific production traffic between H1 and H7 identified by 5-tuple
```
(eth_type,src_ip,src_port,dst_ip,dst_port)=(0x0800, 10.0.0.1, 12345, 10.0.0.7, 54321)
```
by issuing the following REST API call:
```
curl localhost:8080/nmaas/capture_paths/10.0.0.1/12345/10.0.0.7/54321/0x0800
```
One will observe that the controller answers with the possible paths, but cannot decide it yet which practical path will be/have been taken by that traffic.

Next, we manually craft some packets:
Start a terminal on H1, by typing the following into the mininet terminal
```
mininet> xterm h1
```
Once the terminal popped up, start __scapy__, then copy-paste the following lines into its interactive console:
```
>>> for i in range(0,10): sendp(Ether(src='00:00:00:00:00:01', dst='00:00:00:00:00:07')/IP(src='10.0.0.1', dst='10.0.0.7')/TCP(sport=12345,dport=54321), iface='h1-eth0')
```
(One might be required to hit Enter twice to tell the scapy console not to wait for further commands). 

As once can see, this will send out 10 packets from H1 destined to H7 with the specific header information we setup capture rules for.
You can close the terminal of H1 now.

In order to get the traced paths, issue a similar REST API call as before, but now asking for the path itself:
```
$ curl localhost:8080/nmaas/get_paths/10.0.0.1/12345/10.0.0.7/54321/0x0800
```
The controller responses with the taken path promptly. On the other hand, having a look at the controllers output, we can observe that which switches encountered the 10 tagged packets, and whether there were any packet loss.
```
[NMaaS_Network_Controller] - INFO
First-hop switch s1 tagged  20 packets:
[NMaaS_Network_Controller] - INFO
Last-hop switch s5 untagged 20 packets:
[NMaaS_Network_Controller] - INFO
Counting switch s2 encountered 20 packets
```

## Hop-by-Hop End-to-End Latency measurement (HEL)
Now, since the controller is aware of on which path has the application's traffic suffered high latency, it can initiate lightweight network functions on top of the switches to measure the latency in a hop-by-hop manner.
To this end, issue the following command:
```
$ curl localhost:8080 /nmaas/HEL/10.0.0.1/12345/10.0.0.7/54321/0x0800
```
After this the measurement is initiated that will take a couple of seconds (depending on the ping modules settings).
As mentioned above, the mininet network is purposely initiated with different link delays to put the whole story into a meaningful environment. 
Accordingly, the controller will show the hop-by-hop latency data similar to as follows:
```
Latency data from h1 to h7
1 hop: 10.1666666667
2 hop: 2.06833333333
3 hop: 1.09166666667
4 hop: 1.08333333333
```

According to the traversed path, now the network operator has become aware that switch S1 has contributed the most to the end-to-end delay between host H1 and H7, thus further investigation can be carried out in the much smaller problem space, i.e., examining only switch S1 and the link between S1 and S2, instead of examining all possible elements along all possible paths.

Note that all of the above modifications to the insfrastructure (e.g., additional traffic capturing flow rules, packet tagging) are ephimereal and only last until the measurement is done, hence does not have a huge impact on the overall performance.
