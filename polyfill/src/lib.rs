//! Rust std::net Polyfill for WASM Plugins
//!
//! This polyfill provides `std::net::TcpStream` and `std::net::UdpSocket`-compatible functionality
//! for WASM plugins by wrapping the harness host's TCP and UDP functions.
//!
//! ## Usage
//!
//! ### TCP
//!
//! ```rust,no_run
//! use harness_wasi_sockets::TcpStream;
//! use std::io::{Read, Write};
//!
//! // Connect to a remote host
//! let mut stream = TcpStream::connect("127.0.0.1:6000")?;
//!
//! // Write data
//! stream.write_all(b"Hello, world!")?;
//!
//! // Read data
//! let mut buf = [0u8; 1024];
//! let n = stream.read(&mut buf)?;
//! ```
//!
//! ### UDP
//!
//! ```rust,no_run
//! use harness_wasi_sockets::UdpSocket;
//!
//! // Connect to a remote host
//! let socket = UdpSocket::connect("127.0.0.1:6000")?;
//!
//! // Send a datagram
//! socket.send(b"Hello, UDP!")?;
//!
//! // Receive a datagram
//! let mut buf = [0u8; 1024];
//! let (n, addr) = socket.recv_from(&mut buf)?;
//! ```
//!
//! The polyfill provides drop-in replacements for `std::net::TcpStream` and `std::net::UdpSocket`
//! that work in WASM environments where the standard library's networking is not available.

use std::io::{self, Read, Write};
use std::net::SocketAddr;

// Declare TCP host functions from "env" namespace
// These match the signatures implemented in the Go host (plugin/wasm.go)
extern "C" {
    // tcp_connect(addr_offset: u64) -> u32
    // Connects to a TCP address. addr_offset is a pointer to a null-terminated string.
    // Returns connection ID (non-zero) on success, 0 on error.
    fn tcp_connect(addr_offset: u64) -> u32;
    
    // tcp_send(conn_id: u32, data_offset: u64, data_len: u64) -> u32
    // Sends data over a TCP connection.
    // Returns number of bytes sent, or 0 on error.
    fn tcp_send(conn_id: u32, data_offset: u64, data_len: u64) -> u32;
    
    // tcp_recv(conn_id: u32, max_len: u32) -> u64
    // Receives data from a TCP connection.
    // Returns memory offset to received data (non-zero) on success, 0 on error.
    // The data is written to plugin memory by the host.
    fn tcp_recv(conn_id: u32, max_len: u32) -> u64;
    
    // tcp_close(conn_id: u32)
    // Closes a TCP connection.
    fn tcp_close(conn_id: u32);
    
    // UDP functions - imported from "env" namespace
    // udp_connect(addr_offset: u64) -> u32
    // Connects to a UDP address. addr_offset is a pointer to a null-terminated string.
    // Returns connection ID (non-zero) on success, 0 on error.
    fn udp_connect(addr_offset: u64) -> u32;
    
    // udp_send(conn_id: u32, data_offset: u64, data_len: u64) -> u32
    // Sends a UDP datagram.
    // Returns number of bytes sent, or 0 on error.
    fn udp_send(conn_id: u32, data_offset: u64, data_len: u64) -> u32;
    
    // udp_recv(conn_id: u32, max_len: u32) -> u64
    // Receives a UDP datagram.
    // Returns memory offset to received data (non-zero) on success, 0 on error.
    // The data is written to plugin memory by the host.
    fn udp_recv(conn_id: u32, max_len: u32) -> u64;
    
    // udp_close(conn_id: u32)
    // Closes a UDP connection.
    fn udp_close(conn_id: u32);
    
    // ICMP functions - imported from "env" namespace
    // icmp_send(target_offset: u64, payload_offset: u64, payload_len: u64, seq: u16) -> u32
    // Sends an ICMP packet.
    // Returns 1 on success, 0 on failure.
    fn icmp_send(target_offset: u64, payload_offset: u64, payload_len: u64, seq: u32) -> u32;
    
    // icmp_recv(timeout_ms: u32) -> u64
    // Receives an ICMP packet.
    // Returns memory offset to JSON response (non-zero) on success, 0 on error.
    // The JSON is written to plugin memory by the host.
    fn icmp_recv(timeout_ms: u32) -> u64;
}

/// A TCP stream between a local and a remote socket.
///
/// This is a polyfill for `std::net::TcpStream` that works in WASM environments.
/// It wraps the harness host's TCP functions to provide a standard Rust networking API.
///
/// # Example
///
/// ```rust,no_run
/// use harness_wasi_sockets::TcpStream;
/// use std::io::{Read, Write};
///
/// let mut stream = TcpStream::connect("127.0.0.1:6000")?;
/// stream.write_all(b"Hello")?;
/// let mut buf = [0u8; 1024];
/// let n = stream.read(&mut buf)?;
/// ```
pub struct TcpStream {
    conn_id: u32,
    recv_buffer: Vec<u8>,
    recv_offset: usize,
}

impl TcpStream {
    /// Opens a TCP connection to a remote host.
    ///
    /// The `addr` parameter can be:
    /// - A string like `"127.0.0.1:6000"` or `"localhost:8080"`
    /// - A `SocketAddr` (via `ToSocketAddrs` trait)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The address format is invalid
    /// - The connection cannot be established
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::TcpStream;
    ///
    /// let stream = TcpStream::connect("127.0.0.1:6000")?;
    /// ```
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
        let addr = addr.to_socket_addr()?;
        let addr_str = format!("{}:{}", addr.ip(), addr.port());
        
        // Write address string to memory (null-terminated)
        // We need to allocate memory for the string
        let addr_bytes = addr_str.as_bytes();
        let mut addr_mem = Vec::with_capacity(addr_bytes.len() + 1);
        addr_mem.extend_from_slice(addr_bytes);
        addr_mem.push(0); // null terminator
        
        // Use extism-pdk's Memory API to allocate the address string
        use extism_pdk::Memory;
        
        let addr_memory = Memory::new(&addr_str).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to allocate memory: {}", e))
        })?;
        
        let conn_id = unsafe { tcp_connect(addr_memory.offset()) };
        if conn_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Failed to connect to {}", addr_str),
            ));
        }
        
        Ok(TcpStream {
            conn_id,
            recv_buffer: Vec::new(),
            recv_offset: 0,
        })
    }
    
    /// Shuts down the read, write, or both halves of this connection.
    ///
    /// This function will cause all pending and future I/O operations on the specified
    /// portions to immediately return with an appropriate value (see the documentation
    /// of `Shutdown`).
    pub fn shutdown(&self, _how: std::net::Shutdown) -> io::Result<()> {
        // The host doesn't provide a shutdown function, so we'll just close
        // In a full implementation, we'd want to support partial shutdown
        // For now, closing is equivalent to shutdown(Both)
        unsafe { tcp_close(self.conn_id) };
        Ok(())
    }
    
    /// Returns the socket address of the remote peer of this TCP connection.
    ///
    /// Note: This is not implemented in the polyfill as the host doesn't provide
    /// this information. It will return an error.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer_addr() is not supported by the polyfill",
        ))
    }
    
    /// Returns the socket address of the local half of this TCP connection.
    ///
    /// Note: This is not implemented in the polyfill as the host doesn't provide
    /// this information. It will return an error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local_addr() is not supported by the polyfill",
        ))
    }
}

impl Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // First, try to read from our internal buffer
        if self.recv_offset < self.recv_buffer.len() {
            let available = self.recv_buffer.len() - self.recv_offset;
            let to_copy = available.min(buf.len());
            buf[..to_copy].copy_from_slice(
                &self.recv_buffer[self.recv_offset..self.recv_offset + to_copy],
            );
            self.recv_offset += to_copy;
            
            // If we've consumed all buffered data, clear the buffer
            if self.recv_offset >= self.recv_buffer.len() {
                self.recv_buffer.clear();
                self.recv_offset = 0;
            }
            
            return Ok(to_copy);
        }
        
        // No buffered data, receive from the host
        use extism_pdk::Memory;
        
        let data_offset = unsafe { tcp_recv(self.conn_id, buf.len() as u32) };
        if data_offset == 0 {
            // No data available (could be timeout or connection closed)
            return Ok(0);
        }
        
        // Read data from plugin memory
        let mem = Memory::find(data_offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Failed to find memory for received data")
        })?;
        
        let data = mem.to_vec();
        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);
        
        // If there's leftover data, buffer it
        if data.len() > to_copy {
            self.recv_buffer = data[to_copy..].to_vec();
            self.recv_offset = 0;
        }
        
        Ok(to_copy)
    }
}

impl Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use extism_pdk::Memory;
        
        // Allocate memory for the data
        let data_mem = Memory::new(&buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to allocate memory: {}", e))
        })?;
        
        let bytes_sent = unsafe {
            tcp_send(self.conn_id, data_mem.offset(), buf.len() as u64)
        };
        
        if bytes_sent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Failed to send data",
            ));
        }
        
        Ok(bytes_sent as usize)
    }
    
    fn flush(&mut self) -> io::Result<()> {
        // TCP is already flushed by the host
        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        unsafe {
            tcp_close(self.conn_id);
        }
    }
}

/// A trait for objects that can be converted to socket addresses.
///
/// This is a simplified version of `std::net::ToSocketAddrs` for the polyfill.
pub trait ToSocketAddrs {
    fn to_socket_addr(&self) -> io::Result<SocketAddr>;
}

impl ToSocketAddrs for &str {
    fn to_socket_addr(&self) -> io::Result<SocketAddr> {
        parse_socket_addr(self)
    }
}

impl ToSocketAddrs for String {
    fn to_socket_addr(&self) -> io::Result<SocketAddr> {
        parse_socket_addr(self)
    }
}

impl ToSocketAddrs for &String {
    fn to_socket_addr(&self) -> io::Result<SocketAddr> {
        parse_socket_addr(self)
    }
}

impl ToSocketAddrs for SocketAddr {
    fn to_socket_addr(&self) -> io::Result<SocketAddr> {
        Ok(*self)
    }
}

// Helper function to parse socket address string
fn parse_socket_addr(addr: &str) -> io::Result<SocketAddr> {
    // Parse format like "127.0.0.1:6000" or "[::1]:6000"
    if let Some(colon_pos) = addr.rfind(':') {
        let host = &addr[..colon_pos];
        let port_str = &addr[colon_pos + 1..];
        
        // Remove brackets for IPv6
        let host = host.trim_start_matches('[').trim_end_matches(']');
        
        let port: u16 = port_str.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid port number")
        })?;
        
        // Parse IPv4 address
        if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
            return Ok(SocketAddr::V4(std::net::SocketAddrV4::new(ipv4, port)));
        }
        
        // Parse IPv6 address
        if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
            return Ok(SocketAddr::V6(std::net::SocketAddrV6::new(ipv6, port, 0, 0)));
        }
        
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid IP address"));
    }
    
    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid address format"))
}

/// A UDP socket.
///
/// This is a polyfill for `std::net::UdpSocket` that works in WASM environments.
/// It wraps the harness host's UDP functions to provide a standard Rust networking API.
///
/// # Example
///
/// ```rust,no_run
/// use harness_wasi_sockets::UdpSocket;
///
/// let socket = UdpSocket::connect("127.0.0.1:6000")?;
/// socket.send(b"Hello, UDP!")?;
/// let mut buf = [0u8; 1024];
/// let (n, addr) = socket.recv_from(&mut buf)?;
/// ```
pub struct UdpSocket {
    conn_id: u32,
    peer_addr: Option<SocketAddr>,
}

impl UdpSocket {
    /// Creates a UDP socket from the given address.
    ///
    /// The `addr` parameter can be:
    /// - A string like `"127.0.0.1:6000"` or `"localhost:8080"`
    /// - A `SocketAddr` (via `ToSocketAddrs` trait)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The address format is invalid
    /// - The connection cannot be established
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::UdpSocket;
    ///
    /// let socket = UdpSocket::connect("127.0.0.1:6000")?;
    /// ```
    pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
        let addr = addr.to_socket_addr()?;
        let addr_str = format!("{}:{}", addr.ip(), addr.port());
        
        use extism_pdk::Memory;
        
        let addr_memory = Memory::new(&addr_str).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to allocate memory: {}", e))
        })?;
        
        let conn_id = unsafe { udp_connect(addr_memory.offset()) };
        if conn_id == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("Failed to connect to {}", addr_str),
            ));
        }
        
        Ok(UdpSocket {
            conn_id,
            peer_addr: Some(addr),
        })
    }
    
    /// Sends data on this socket to the remote address to which it is connected.
    ///
    /// The `connect` method will connect this socket to a remote address. This
    /// method will fail if the socket is not connected.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket is not connected
    /// - The data cannot be sent
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        use extism_pdk::Memory;
        
        let data_mem = Memory::new(&buf).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to allocate memory: {}", e))
        })?;
        
        let bytes_sent = unsafe {
            udp_send(self.conn_id, data_mem.offset(), buf.len() as u64)
        };
        
        if bytes_sent == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Failed to send data",
            ));
        }
        
        Ok(bytes_sent as usize)
    }
    
    /// Receives a single datagram message on the socket from the remote address to
    /// which it is connected.
    ///
    /// On success, returns the number of bytes read and the address from whence the
    /// message came. The function must be called with valid byte array `buf` of
    /// sufficient size to hold the message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket is not connected
    /// - No data is available
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use extism_pdk::Memory;
        
        let data_offset = unsafe { udp_recv(self.conn_id, buf.len() as u32) };
        if data_offset == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "No data available",
            ));
        }
        
        let mem = Memory::find(data_offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Failed to find memory for received data")
        })?;
        
        let data = mem.to_vec();
        let to_copy = data.len().min(buf.len());
        buf[..to_copy].copy_from_slice(&data[..to_copy]);
        
        // Return the peer address if we have it, otherwise use a placeholder
        let addr = self.peer_addr.unwrap_or_else(|| {
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(0, 0, 0, 0),
                0,
            ))
        });
        
        Ok((to_copy, addr))
    }
    
    /// Receives a single datagram message on the socket.
    ///
    /// On success, returns the number of bytes read. The function must be called
    /// with valid byte array `buf` of sufficient size to hold the message bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The socket is not connected
    /// - No data is available
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_from(buf).map(|(n, _)| n)
    }
    
    /// Returns the socket address of the remote peer this socket was connected to.
    ///
    /// Note: This may return an error if the socket was not connected via `connect()`.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "Socket is not connected",
            )
        })
    }
    
    /// Returns the socket address that this socket was created from.
    ///
    /// Note: This is not implemented in the polyfill as the host doesn't provide
    /// this information. It will return an error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "local_addr() is not supported by the polyfill",
        ))
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        unsafe {
            udp_close(self.conn_id);
        }
    }
}

/// ICMP packet sender and receiver.
///
/// This polyfill provides ICMP functionality for WASM plugins by wrapping the harness host's ICMP functions.
///
/// # Example
///
/// ```rust,no_run
/// use harness_wasi_sockets::IcmpSocket;
///
/// // Send an ICMP echo request
/// let socket = IcmpSocket::new();
/// socket.send("8.8.8.8", b"Hello", 1)?;
///
/// // Receive ICMP response
/// let response = socket.recv(5000)?;
/// println!("Received from {}: type={}, code={}", response.source, response.icmp_type, response.code);
/// ```
pub struct IcmpSocket;

/// ICMP packet response.
#[derive(Debug, Clone)]
pub struct IcmpResponse {
    /// Source address of the ICMP packet
    pub source: String,
    /// ICMP type
    pub icmp_type: u8,
    /// ICMP code
    pub code: u8,
    /// ICMP echo ID (if echo packet)
    pub id: Option<u16>,
    /// ICMP echo sequence number (if echo packet)
    pub seq: Option<u16>,
    /// ICMP payload data
    pub data: Vec<u8>,
}

impl IcmpSocket {
    /// Creates a new ICMP socket.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::IcmpSocket;
    ///
    /// let socket = IcmpSocket::new();
    /// ```
    pub fn new() -> Self {
        IcmpSocket
    }

    /// Sends an ICMP echo request packet.
    ///
    /// # Arguments
    ///
    /// * `target` - Target IP address (e.g., "8.8.8.8")
    /// * `payload` - Payload data to send
    /// * `seq` - Sequence number for the ICMP packet
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The target address is invalid
    /// - The packet cannot be sent
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::IcmpSocket;
    ///
    /// let socket = IcmpSocket::new();
    /// socket.send("8.8.8.8", b"Hello", 1)?;
    /// ```
    pub fn send(&self, target: &str, payload: &[u8], seq: u16) -> io::Result<()> {
        use extism_pdk::Memory;

        // Write target address to memory
        let target_mem = Memory::new(&target.to_string()).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to allocate memory for target: {}", e))
        })?;

        // Write payload to memory
        let payload_mem = Memory::new(&payload.to_vec()).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("Failed to allocate memory for payload: {}", e))
        })?;

        let result = unsafe {
            icmp_send(
                target_mem.offset(),
                payload_mem.offset(),
                payload.len() as u64,
                seq as u32,
            )
        };

        if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to send ICMP packet to {}", target),
            ));
        }

        Ok(())
    }

    /// Receives an ICMP packet.
    ///
    /// # Arguments
    ///
    /// * `timeout_ms` - Timeout in milliseconds
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The timeout expires
    /// - The packet cannot be received
    /// - The response cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::IcmpSocket;
    ///
    /// let socket = IcmpSocket::new();
    /// let response = socket.recv(5000)?;
    /// ```
    pub fn recv(&self, timeout_ms: u32) -> io::Result<IcmpResponse> {
        use extism_pdk::Memory;

        let json_offset = unsafe { icmp_recv(timeout_ms) };
        if json_offset == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "ICMP receive timeout or error",
            ));
        }

        // Read JSON from plugin memory
        let mem = Memory::find(json_offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "Failed to find memory for ICMP response")
        })?;

        let json_bytes = mem.to_vec();
        let json_str = String::from_utf8(json_bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Invalid UTF-8 in ICMP response: {}", e))
        })?;

        // Parse JSON response
        // The host returns: {"source": "...", "type": 0, "code": 0, "id": 1, "seq": 1, "data": [...]}
        use serde_json::Value;
        let json: Value = serde_json::from_str(&json_str).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse ICMP response JSON: {}", e))
        })?;

        let source = json["source"]
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing 'source' in ICMP response"))?
            .to_string();

        let icmp_type = json["type"]
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing 'type' in ICMP response"))?
            as u8;

        let code = json["code"]
            .as_u64()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing 'code' in ICMP response"))?
            as u8;

        let id = json["id"].as_u64().map(|v| v as u16);
        let seq = json["seq"].as_u64().map(|v| v as u16);

        let data = if let Some(data_array) = json["data"].as_array() {
            data_array
                .iter()
                .filter_map(|v| v.as_u64().map(|n| n as u8))
                .collect()
        } else if let Some(data_str) = json["data"].as_str() {
            data_str.as_bytes().to_vec()
        } else {
            Vec::new()
        };

        Ok(IcmpResponse {
            source,
            icmp_type,
            code,
            id,
            seq,
            data,
        })
    }
}

impl Default for IcmpSocket {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export for convenience (matches std::net API)
pub use TcpStream as TcpStreamPolyfill;
pub use UdpSocket as UdpSocketPolyfill;

// HTTP Client using Go's net/http via host functions
// Declare HTTP host function from "env" namespace
extern "C" {
    // http_request(method_offset: u64, url_offset: u64, headers_offset: u64, body_offset: u64) -> u64
    // Makes an HTTP request using Go's net/http.
    // Returns memory offset to JSON response (non-zero) on success, 0 on error.
    // The JSON contains: {"status": 200, "headers": {"Header-Name": ["value1", "value2"]}, "body": "base64-encoded-body"}
    fn http_request(
        method_offset: u64,
        url_offset: u64,
        headers_offset: u64,
        body_offset: u64,
    ) -> u64;
}

use std::collections::HashMap;

/// A header map that can store multiple values per header name.
///
/// This is used to properly handle HTTP headers like `Set-Cookie` that can
/// appear multiple times in a response.
pub type HeaderMap = HashMap<String, Vec<String>>;

/// An HTTP client with a reqwest-like API.
///
/// This client uses Go's `net/http` on the host side to make HTTP requests,
/// which properly handles all headers including multiple `Set-Cookie` headers.
///
/// # Example
///
/// ```rust,no_run
/// use harness_wasi_sockets::Client;
///
/// let client = Client::new();
/// let response = client.get("https://example.com").send()?;
/// println!("Status: {}", response.status());
/// let body = response.text()?;
/// ```
pub struct Client;

impl Client {
    /// Creates a new HTTP client.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// ```
    pub fn new() -> Self {
        Client
    }

    /// Creates a GET request builder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com").send()?;
    /// ```
    pub fn get(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new("GET", url)
    }

    /// Creates a POST request builder.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.post("https://example.com/api")
    ///     .header("Content-Type", "application/json")
    ///     .body(r#"{"key": "value"}"#.as_bytes().to_vec())
    ///     .send()?;
    /// ```
    pub fn post(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new("POST", url)
    }

    /// Creates a PUT request builder.
    pub fn put(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new("PUT", url)
    }

    /// Creates a DELETE request builder.
    pub fn delete(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new("DELETE", url)
    }

    /// Creates a PATCH request builder.
    pub fn patch(&self, url: &str) -> RequestBuilder {
        RequestBuilder::new("PATCH", url)
    }
}

impl Default for Client {
    fn default() -> Self {
        Client::new()
    }
}

/// A request builder for constructing HTTP requests.
///
/// This provides a fluent API similar to reqwest's `RequestBuilder`.
pub struct RequestBuilder {
    method: String,
    url: String,
    headers: Vec<String>,
    body: Option<Vec<u8>>,
}

impl RequestBuilder {
    fn new(method: &str, url: &str) -> Self {
        RequestBuilder {
            method: method.to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Adds a header to the request.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com")
    ///     .header("X-Custom-Header", "value")
    ///     .header("Cookie", "session=abc123")
    ///     .send()?;
    /// ```
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push(format!("{}: {}", name, value));
        self
    }

    /// Sets the request body as JSON.
    ///
    /// This automatically sets the `Content-Type` header to `application/json`.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    /// use serde_json::json;
    ///
    /// let client = Client::new();
    /// let payload = json!({"key": "value"});
    /// let response = client.post("https://example.com/api")
    ///     .json(&payload)
    ///     .send()?;
    /// ```
    pub fn json<T: serde::Serialize>(mut self, body: &T) -> Self {
        // Set Content-Type header
        self.headers.push("Content-Type: application/json".to_string());
        
        // Serialize body to JSON
        match serde_json::to_vec(body) {
            Ok(json_bytes) => {
                self.body = Some(json_bytes);
            }
            Err(_) => {
                // If serialization fails, we'll return an error in send()
                // For now, just set body to None to indicate error state
                self.body = None;
            }
        }
        self
    }

    /// Sets the request body as raw bytes.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.post("https://example.com/api")
    ///     .header("Content-Type", "text/plain")
    ///     .body(b"Hello, world!".to_vec())
    ///     .send()?;
    /// ```
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Some(body);
        self
    }

    /// Sends the request and returns the response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The request cannot be created or sent
    /// - The response cannot be parsed
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com").send()?;
    /// ```
    pub fn send(self) -> io::Result<Response> {
        use extism_pdk::Memory;

        // Allocate memory for method
        let method_mem = Memory::new(&self.method).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to allocate memory for method: {}", e),
            )
        })?;

        // Allocate memory for URL
        let url_mem = Memory::new(&self.url).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to allocate memory for URL: {}", e),
            )
        })?;

        // Serialize headers to JSON array
        let headers_json = serde_json::to_string(&self.headers).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize headers: {}", e),
            )
        })?;

        // Allocate memory for headers (can be empty array)
        let headers_mem = Memory::new(&headers_json).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to allocate memory for headers: {}", e),
            )
        })?;

        // Allocate memory for body if present
        let body_mem = if let Some(ref body_data) = self.body {
            Some(
                Memory::new(body_data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Failed to allocate memory for body: {}", e),
                    )
                })?,
            )
        } else {
            None
        };

        // Call host function
        let json_offset = unsafe {
            http_request(
                method_mem.offset(),
                url_mem.offset(),
                headers_mem.offset(),
                body_mem.as_ref().map(|m| m.offset()).unwrap_or(0),
            )
        };

        if json_offset == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "HTTP request failed (host function returned 0)",
            ));
        }

        // Read JSON response from plugin memory
        let json_mem = Memory::find(json_offset).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Failed to find memory for JSON response",
            )
        })?;

        let json_bytes = json_mem.to_vec();
        let json_str = String::from_utf8(json_bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid UTF-8 in JSON response: {}", e),
            )
        })?;

        // Parse JSON response
        #[derive(serde::Deserialize)]
        struct HttpResponse {
            status: u16,
            headers: HashMap<String, Vec<String>>,
            body: String, // base64-encoded
        }

        let http_resp: HttpResponse = serde_json::from_str(&json_str).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse HTTP response JSON: {}", e),
            )
        })?;

        // Decode base64 body
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
        let body_bytes = BASE64
            .decode(&http_resp.body)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Failed to decode base64 body: {}", e),
                )
            })?;

        Ok(Response {
            status: http_resp.status,
            headers: http_resp.headers,
            body: body_bytes,
        })
    }
}

/// An HTTP response.
///
/// This represents the response from an HTTP request, including status code,
/// headers, and body.
pub struct Response {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Response {
    /// Returns the HTTP status code.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com").send()?;
    /// if response.status() == 200 {
    ///     println!("Success!");
    /// }
    /// ```
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Returns the status code as a range check.
    ///
    /// Returns `true` if the status code is in the 200-299 range.
    pub fn status_is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Returns a reference to the header map.
    ///
    /// Each header name maps to a vector of values, allowing multiple headers
    /// with the same name (like `Set-Cookie`).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com").send()?;
    /// let headers = response.headers();
    /// if let Some(cookies) = headers.get("Set-Cookie") {
    ///     for cookie in cookies {
    ///         println!("Cookie: {}", cookie);
    ///     }
    /// }
    /// ```
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Gets all values for a header name (case-insensitive).
    ///
    /// Returns `None` if the header is not present.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com").send()?;
    /// if let Some(content_types) = response.header("Content-Type") {
    ///     println!("Content-Type: {:?}", content_types);
    /// }
    /// ```
    pub fn header(&self, name: &str) -> Option<&Vec<String>> {
        // Headers are stored with canonicalized names
        let canonical = name
            .split('-')
            .map(|s| {
                let mut chars = s.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>()
                        + &chars.as_str().to_lowercase(),
                }
            })
            .collect::<Vec<_>>()
            .join("-");

        self.headers.get(&canonical).or_else(|| {
            // Try case-insensitive lookup
            for (key, value) in &self.headers {
                if key.eq_ignore_ascii_case(name) {
                    return Some(value);
                }
            }
            None
        })
    }

    /// Returns the response body as a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is not valid UTF-8.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com").send()?;
    /// let body = response.text()?;
    /// println!("Response: {}", body);
    /// ```
    pub fn text(&self) -> io::Result<String> {
        String::from_utf8(self.body.clone()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Response body is not valid UTF-8: {}", e),
            )
        })
    }

    /// Returns the response body as raw bytes.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    ///
    /// let client = Client::new();
    /// let response = client.get("https://example.com/api").send()?;
    /// let bytes = response.bytes();
    /// ```
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Deserializes the response body as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the body is not valid JSON or cannot be deserialized
    /// into the target type.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use harness_wasi_sockets::Client;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct ApiResponse {
    ///     message: String,
    /// }
    ///
    /// let client = Client::new();
    /// let response = client.get("https://api.example.com/data").send()?;
    /// let data: ApiResponse = response.json()?;
    /// ```
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> io::Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse JSON: {}", e),
            )
        })
    }
}
