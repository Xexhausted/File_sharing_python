# P2P File Sharing System

A distributed Peer-to-Peer (P2P) file sharing application built with Python. It functions as a Servent (Server + Client), allowing users to slice, encrypt, share, and download files concurrently using `asyncio`.

## Features

*   **Distributed Architecture:** Every node is both a client and a server.
*   **Security:** Symmetric encryption (Fernet) for all network traffic.
*   **File Slicing:** Files are split into 1MB chunks for efficient transfer.
*   **Integrity:** SHA-256 verification for every chunk and the final reassembled file.
*   **Dockerized:** Easy deployment using Docker and Docker Compose.
*   **GUI & CLI:** Includes a CLI and a modern, dark-themed GUI built with CustomTkinter.

---

## Prerequisites

*   **Docker** & **Docker Compose** (Recommended)
*   **Python 3.10+** (If running locally without Docker)

---

## Quick Start (Docker)

The easiest way to run the application is using Docker. This ensures all dependencies are installed and provides an isolated environment.

### 1. Build and Start the Node

Open a terminal in the project root and run:

```bash
docker-compose up -d --build
```

### 2. Attach to the Node

To interact with the running node (CLI), attach your terminal to the container:

```bash
docker attach p2p_node
```

*(If you don't see a prompt immediately, press `Enter`)*

### 3. Detach (Exit without stopping)

To leave the container running in the background, press:  
`Ctrl + P`, then `Ctrl + Q`.

---

## Running Locally (Python)

If you prefer to run it directly on your machine:

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the CLI:**
    ```bash
    # Usage: python src/main.py [PORT]
    python src/main.py 8888
    ```

3.  **Run the GUI:**
    ```bash
    # Usage: python src/gui.py [PORT]
    python src/gui.py 8888
    ```

---

## Usage Guide

Once the application is running, you can use the following commands:

### Share a File
Slices a local file and makes it available to the network.
```text
share <filepath>
# Example: share test.txt
```
*Copy the **File Hash** returned by this command.*

### Download a File
Connects to a peer and downloads a file using its hash.
```text
download <PEER_IP> <PEER_PORT> <FILE_HASH>
# Example: download 192.168.1.5 8888 a1b2c3d4...
```

### List Files
Shows files currently in your shared storage directory.
```text
ls
```

---

## Multi-PC Setup

To run this on two different computers (PC A and PC B):

1.  **Copy the Project:** Ensure the entire project folder is on both PCs.
2.  **Sync Key:** Copy the `secret.key` file from PC A to PC B. **They must match.**
3.  **Start Nodes:** Run `docker-compose up -d` on both PCs.
4.  **Connect:**
    *   On PC A: `share my_video.mp4` (Copy the Hash).
    *   On PC B: `download <IP_OF_PC_A> 8888 <HASH>`.

*Note: Ensure your firewall allows traffic on port 8888.*
