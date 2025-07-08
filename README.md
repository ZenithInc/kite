<p align="center">
  <a href="https://github.com/ZenithInc/laravel-plus">
   <img alt="Laravel-Plus-Logo" src="https://i.miji.bid/2025/07/09/4aee22fdfdb52e55c49a84ada987728a.png">
  </a>
</p>
# Kite

A secure and efficient HTTP/HTTPS proxy server and client written in Rust.

## Features

- HTTP and HTTPS proxy support
- Client-server architecture
- Secure communication with AES-256-GCM encryption
- Multiple proxy modes:
  - HTTP proxy
  - Transparent proxy
- Authentication mechanism
- Asynchronous I/O with Tokio
- Configurable via TOML files

## Installation

### Prerequisites

- Rust and Cargo (1.75.0 or later recommended)

### Building from source

```bash
# Clone the repository
git clone https://github.com/yourusername/proxy-rs.git
cd proxy-rs

# Build the project
cargo build --release

# The binaries will be available in target/release/
```

## Usage

### Server

1. Configure the server by editing `config/server.toml`:

```toml
bind_addr = "0.0.0.0:1024"  # Address and port to listen on
auth_key = "your_secret_key"  # Authentication key
```

2. Run the server:

```bash
cargo run --bin server
# Or use the binary directly
./target/release/server
```

### Client

1. Configure the client by editing `config/client.toml`:

```toml
local_addr = "127.0.0.1:8888"  # Local address and port to listen on
server_addr = "http://server_ip:1024"  # Address of the proxy server
auth_key = "your_secret_key"  # Authentication key (must match server)
mode = "Http"  # Proxy mode: Http, Socks5, or Transparent
```

2. Run the client:

```bash
cargo run --bin client
# Or use the binary directly
./target/release/client
```

3. Configure your browser or application to use the proxy at the address specified in `local_addr` (e.g., 127.0.0.1:8888).

## Configuration

### Server Configuration

| Option      | Description                                                   |
|-------------|---------------------------------------------------------------|
| `bind_addr` | The address and port where the server listens for connections |
| `auth_key`  | Secret key used for client authentication                     |
| `cert_path` | (Optional) Path to TLS certificate for HTTPS                  |
| `key_path`  | (Optional) Path to TLS private key for HTTPS                  |

### Client Configuration

| Option | Description |
|--------|-------------|
| `local_addr` | The address and port where the client listens for connections |
| `server_addr` | The URL of the proxy server |
| `auth_key` | Secret key for server authentication |
| `mode` | Proxy mode: Http, Socks5, or Transparent |

## Security

- All communication between client and server is encrypted using AES-256-GCM
- Authentication is required for all connections
- Passwords are hashed using SHA-256

## License

The kite is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).
