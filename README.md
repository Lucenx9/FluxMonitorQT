# FluxMonitorQT

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![Qt](https://img.shields.io/badge/Qt-%23217346.svg?style=for-the-badge&logo=Qt&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)

**FluxMonitorQT** is a modern, high-performance network connection monitor built with **Rust** and **Qt5**. It provides real-time visibility into active network connections, process associations, and bandwidth usage with a sleek, native interface.

## 🚀 Features

*   **Real-time Monitoring**: Live tracking of TCP and UDP connections.
*   **Process Identification**: Associates network sockets with PIDs, names, and command lines.
*   **Advanced Filtering**: Filter by Host, Port, Protocol, and exclude Localhost.
*   **Traffic Stats**: Monitor upload/download speeds per connection (aggregated interface stats).
*   **System Tray Integration**: Minimized background operation.
*   **Professional UI**: Interactive sortable columns and resizing.
*   **Security Aware**: Clearly indicates when elevated permissions are needed to inspect system processes.

## 🛠️ Prerequisites

*   **Rust** (Latest Stable)
*   **Qt5 Development Libraries** (`qt5-default`, `qtbase5-dev`, etc.)
*   **Build Essentials** (`build-essential`, `libncurses-dev`, etc.)

## 📦 Installation for Users

### Clone the Repository
```bash
git clone https://github.com/Lucenx9/FluxMonitorQT.git
cd FluxMonitorQT
```

### Build
We provide a helper script to ensure the correct Qt version is linked:

```bash
./build.sh
```

## 🖥️ Usage

To launch the application:

```bash
./run.sh
```

### 🔐 Full System Visibility (Root)
By default, Linux restricts access to process network information for security reasons. If run as a standard user, you will only see your own processes.

To see **ALL** system connections (including root processes), launch with `sudo`:

```bash
sudo ./run.sh
```

## 🔧 Troubleshooting

### "Unknown" Processes
If you see "System / Elevated" or "Access Restricted", it means the application doesn't have permission to read that process's details. **Run with `sudo` to resolve this.**

### Qt5 vs Qt6 Conflict
The build scripts (`build.sh`, `run.sh`) are configured to force Qt5 usage (`QMAKE=qmake-qt5`) to prevent linker errors if both Qt major versions are installed.

## 📄 License

This project is licensed under the MIT License.
