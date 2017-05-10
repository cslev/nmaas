# End-host Driven Troubleshooting (EDT) Architecture for Software-Defined Networking

## Requirements:
 - Mininet environment
 - Ryu controller
 - curl for interacting with the controller
 
## Quick Walkthrough:
 The Proof-of-Concept of EDT is written in a way to demonstrate its process step by step, thus it is not working automatically. It provides a REST API for users/developers wishing to get their hands dirty with the architecture.
###### First, download the source into ryu/ryu/app/ directory:
```
$ cd $HOME/ryu/ryu/app/
$ git clone https://github.com/cslev/nmaas
```
This will create an nmaas directory under ryu/ryu/app.
In the directory, you will find several python files, however only two of them are worth noting here, which are __nmaas_network.py__ (for firing up a mininet topology with hosts and switches) and __nmaas_controller.py__ (the SDN controller).  
###### nmaas_controller.py
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
Before getting into details, initiate the topology as well:
```
$ cd $HOME/ryu/ryu/app/nmaas
$ sudo mn --clean; sudo python nmaas_network.py;
```
