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

// Re-export for convenience (matches std::net API)
pub use TcpStream as TcpStreamPolyfill;
pub use UdpSocket as UdpSocketPolyfill;
