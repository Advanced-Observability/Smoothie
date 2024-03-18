# Smoothie: Dynamic Path Load Balancer for Data Center Networks

## Overview

Smoothie is a dynamic path load balancer specifically designed for real-time congestion management in contemporary Data Center Networks (DCNs). It optimizes resource utilization and prevents congestion by leveraging Inband Network Telemetry (INT) for collecting network state information and Segment Routing Version 6 (SRv6) for rerouting traffic. Built with the programmable P4 programming language, Smoothie effectively achieves its goals, showcasing superior performance over conventional Equal-Cost Multipath (ECMP) routing and competitive results compared to other congestion-aware load balancing solutions (CLOVE).

### Code Base for INT and SRv6

Smoothie's development draws inspiration from and collaborates with existing projects in the domains of Inband Network Telemetry (INT) and Segment Routing Version 6 (SRv6). The code base for INT can be found at [INT Platforms](https://github.com/GEANT-DataPlaneProgramming/int-platforms), and for SRv6, you can refer to [NGSDN Tutorial](https://github.com/opennetworkinglab/ngsdn-tutorial).

## Key Features

- **Proactive Congestion Response:** Smoothie minimizes the necessity for TCP congestion window resizing by employing proactive congestion response mechanisms.
- **Intelligent Rerouting:** The ability to intelligently reroute flows onto optimal paths substantially reduces route flapping, enhancing overall network stability.
- **P4 Programmability:** Leveraging the programmable nature of the P4 programming language for dynamic and efficient network management.
- **Inband Network Telemetry (INT):** Collecting real-time network state information for effective congestion management.
- **Segment Routing Version 6 (SRv6):** Rerouting traffic dynamically to optimize resource utilization.
- **Centralized Controller:** Enhanced manageability, ease of maintenance, and simplified deployment through a centralized controller.

## Additionnal information

Check our paper at [paper](https://hdl.handle.net/2268/313339)

## Getting Started

### Prerequisites

Before diving into Smoothie, make sure you have [p4utils](https://github.com/nsg-ethz/p4-utils) installed. This essential toolkit provides the necessary utilities for Smoothie's seamless integration and operation.

### Installation Steps

Follow these steps to get Smoothie up and running on your system:

1. Clone the Smoothie repository:

```bash
git clone https://github.com/Advanced-Observability/Smoothie.git
```
2. Navigate to the project directory:

```bash
cd Smoothie
```
### Launch in Benchmark mode

```bash
python app.py --config topos/test.json
```

This command initializes Smoothie with the specified configuration file (`topos/test.json`) to start benchmarking. Feel free to explore different configurations based on your network topology and requirements.

## Contributing

We welcome contributions! If you'd like to contribute to Smoothie, feel free to contact us (see contact informations below).

## License

Smoothie is licensed under the [MIT License](link-to-license).

## Acknowledgments

We would like to acknowledge [contributors](https://scholar.google.com/citations?user=NFa1AfIAAAAJ&hl=en) who have contributed to the development of Smoothie.

## Contact

For any questions or issues, feel free to contact us at [lchampagne@uliege.be](mailto:lchampagne@uliege.be).