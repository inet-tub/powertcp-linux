# PowerTCP for Linux
This repository presents an implementation of the PowerTCP congestion control
for the Linux kernel. The two variants of PowerTCP are provided as separate
congestion control algorithms:
- the telemetry-based *PowerTCP* and
- the simplified, timing-based *RTT-PowerTCP* (called *θ-PowerTCP* in the
  [paper](#for-powertcp)).

Please see the [references](#references) for background on this work.

This repository contains two implementations of PowerTCP: a kernel module and an
eBPF program. 

## Step-by-step instructions

The main focus of this work is on the eBPF implementation. Follow its
[instructions](bpf/README.md) for experimenting with it.

There is also a proof-of-concept implementation as a kernel module, see its
[instructions](doc/module.md).

## Implementation details
There is *some* documentation on aspects of the implementation(s) in
[doc/](doc/).

## References

### For the work in this repository
> Jörn-Thorben Hinz, Vamsi Addanki, Csaba Györgyi, Theo Jepsen, and Stefan Schmid.  
> “TCP's Third Eye: Leveraging eBPF for Telemetry-Powered Congestion Control”  
> In *Proceedings of the 1st Workshop on eBPF and Kernel Extensions*, pp. 1-7. 2023.

https://doi.org/10.1145/3609021.3609295

<details>
<summary>Click for BibTex citation</summary>

```bib
@inproceedings{tcpsthirdeye,
author = {Hinz, J\"{o}rn-Thorben and Addanki, Vamsi and Gy\"{o}rgyi, Csaba and Jepsen, Theo and Schmid, Stefan},
title = {TCP's Third Eye: Leveraging EBPF for Telemetry-Powered Congestion Control},
year = {2023},
isbn = {9798400702938},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3609021.3609295},
doi = {10.1145/3609021.3609295},
booktitle = {Proceedings of the 1st Workshop on EBPF and Kernel Extensions},
pages = {1–7},
numpages = {7},
keywords = {eBPF, datacenter, INT, congestion control, TCP, linux kernel},
location = {New York, NY, USA},
series = {eBPF '23}
}
```

</details>

### For PowerTCP
> Vamsi Addanki, Oliver Michel, and Stefan Schmid.  
> “PowerTCP: Pushing the Performance Limits of Datacenter NEtworks”  
> In *19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22)*, pp. 51-70. 2022.

https://www.usenix.org/conference/nsdi22/presentation/addanki

<details>
<summary>Click for BibTex citation</summary>

```bib
@inproceedings{powertcp,
author = {Vamsi Addanki and Oliver Michel and Stefan Schmid},
title = {{PowerTCP}: Pushing the Performance Limits of Datacenter Networks},
booktitle = {19th USENIX Symposium on Networked Systems Design and Implementation (NSDI 22)},
year = {2022},
isbn = {978-1-939133-27-4},
address = {Renton, WA},
pages = {51--70},
url = {https://www.usenix.org/conference/nsdi22/presentation/addanki},
publisher = {USENIX Association},
month = apr
}
```

</details>

### For TCP-INT
> Grzegorz Jereczek, Theo Jepsen, Simon Wass, Bimmy Pujari, Jerry Zhen, and Jeongkeun Lee.  
> “TCP-INT: Lightweight Network Telemetry with TCP Transport”  
> In *Proceedings of the SIGCOMM'22 Poster and Demo Sessions*, pp. 58-60. 2022.

https://doi.org/10.1145/3546037.3546064

<details>
<summary>Click for BibTex citation</summary>

```bib
@inproceedings{tcpint,
author = {Jereczek, Grzegorz and Jepsen, Theo and Wass, Simon and Pujari, Bimmy and Zhen, Jerry and Lee, Jeongkeun},
title = {TCP-INT: Lightweight Network Telemetry with TCP Transport},
year = {2022},
isbn = {9781450394345},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3546037.3546064},
doi = {10.1145/3546037.3546064},
pages = {58–60},
numpages = {3},
keywords = {in-band network telemetry, network monitoring},
location = {Amsterdam, Netherlands},
series = {SIGCOMM '22}
}
```

</details>
