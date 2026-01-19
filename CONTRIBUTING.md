# Contributing to Cpp-VPN-Core

Thank you for your interest in contributing to the project. Cpp-VPN-Core is a high-performance networking engine, and contributions that improve throughput, reduce latency, or enhance architectural resilience are welcome.

## Open Source Licensing
This project is licensed under the **Apache License 2.0**. By contributing to this repository, you agree that your contributions will be licensed under the same terms. The Apache 2.0 license provides an explicit grant of patent rights from contributors to users, ensuring the project remains a safe and professional foundation for the community.

## How to Contribute

### 1. Reporting Technical Issues
If you identify a performance bottleneck, memory leak, or a kernel-level conflict, please open a GitHub Issue. To provide a high-quality report, include:
* **Environment:** Linux Kernel version and distribution.
* **Trace Data:** Relevant output from the internal `LOG` utility.
* **Context:** A clear description of the network conditions or load during the failure.

### 2. Architectural Discussion
I welcome in-depth peer reviews regarding the system's core logic, such as the `recvmmsg` batching implementation, session roaming strategies, or cryptographic optimizations. Please open an issue with the label `discussion` to start a technical dialogue.

### 3. Code Submissions
If you wish to submit a patch or a new feature:
1. **Fork** the repository and create your branch from `master`.
2. Ensure your code adheres to the **Technical Standards** listed below.
3. Submit a Pull Request with a detailed description of the changes and their impact on performance or stability.

---

## Technical Standards & Style
To maintain the performance integrity of the core engine, all contributions must adhere to the following:

* **Language Standard:** C++17.
* **Resource Management:** Strict adherence to **RAII** (Resource Acquisition Is Initialization).
* **Performance Goal:** Maintain a **Zero-Allocation** strategy within the primary packet-processing loop to avoid heap fragmentation and latency spikes.
* **Modern C++:** Use of smart pointers over raw pointers is preferred except where direct kernel interfacing is required.
* **Documentation:** All public interfaces must be documented in the header files.

---

## Code of Conduct
This project follows a professional standard of conduct. We expect all contributors to communicate with technical rigor and mutual respect.