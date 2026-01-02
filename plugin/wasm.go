package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	extism "github.com/extism/go-sdk"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func init() {
	RegisterLoader("wasm", func() (Loader, error) {
		return NewWASMLoader()
	})
}

// WASMLoader loads WASM plugins using Extism SDK.
type WASMLoader struct{}

// NewWASMLoader creates a new WASM loader.
func NewWASMLoader() (*WASMLoader, error) {
	return &WASMLoader{}, nil
}

// Load compiles and instantiates a WASM plugin from raw bytes.
func (wl *WASMLoader) Load(data []byte, name string) (Plugin, error) {
	manifest := extism.Manifest{
		Wasm: []extism.Wasm{
			extism.WasmData{Data: data},
		},
		AllowedHosts: []string{"*"},
	}

	ctx := context.Background()
	config := extism.PluginConfig{
		EnableWasi: true,
	}

	// Register host functions for network operations
	// These match the exact WASM import signatures from the compiled plugin
	hostFunctions := []extism.HostFunction{
		// TCP functions - imported from "env" module
		newTCPConnectFunction(),
		newTCPSendFunction(),
		newTCPRecvFunction(),
		newTCPCloseFunction(),
		// UDP functions - imported from "env" module
		newUDPConnectFunction(),
		newUDPSendFunction(),
		newUDPRecvFunction(),
		newUDPCloseFunction(),
		// ICMP functions - imported from "env" module
		newICMPSendFunction(),
		newICMPRecvFunction(),
	}

	plugin, err := extism.NewPlugin(ctx, manifest, config, hostFunctions)
	if err != nil {
		return nil, fmt.Errorf("failed to create Extism plugin: %w", err)
	}

	return &WASMPlugin{
		name:   name,
		plugin: plugin,
		ctx:    ctx,
	}, nil
}

// WASMPlugin implements the Plugin interface for WASM modules.
type WASMPlugin struct {
	name   string
	plugin *extism.Plugin
	ctx    context.Context
}

// Close shuts down the plugin instance and releases resources.
func (wp *WASMPlugin) Close() error {
	if wp.plugin != nil {
		return wp.plugin.Close(wp.ctx)
	}
	return nil
}

// Name returns the plugin name, preferring the WASM exported name().
func (wp *WASMPlugin) Name() string {
	result, err := wp.callStringFunction("name")
	if err == nil && result != "" {
		return result
	}
	return wp.name
}

// Description returns the plugin description by calling description().
func (wp *WASMPlugin) Description() string {
	result, err := wp.callStringFunction("description")
	if err != nil {
		return "WASM plugin"
	}
	return result
}

// JSONSchema fetches the plugin schema via json_schema().
func (wp *WASMPlugin) JSONSchema() json.RawMessage {
	result, err := wp.callStringFunction("json_schema")
	if err != nil {
		return json.RawMessage("{}")
	}
	return json.RawMessage(result)
}

// Execute calls the exported execute() function using Extism's input/output pattern.
// The function reads JSON args from input and writes JSON result to output.
func (wp *WASMPlugin) Execute(ctx context.Context, args json.RawMessage) (interface{}, error) {
	argsBytes := []byte(string(args))

	// Call execute function with JSON args as input data
	// The function reads input via extism_input_load and writes output via extism_output_set
	exitCode, resultBytes, err := wp.plugin.Call("execute", argsBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to execute WASM function: %w", err)
	}
	if exitCode != 0 {
		return nil, fmt.Errorf("execute function returned non-zero exit code: %d", exitCode)
	}

	// Extism's Call() returns the output bytes directly (set via extism_output_set)
	if len(resultBytes) == 0 {
		return nil, fmt.Errorf("execute function returned empty result")
	}

	// Parse JSON result
	var result interface{}
	if err := json.Unmarshal(resultBytes, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON result: %w", err)
	}

	return result, nil
}

// callStringFunction calls a WASM function that uses Extism's input/output pattern.
// The function reads no input and writes output directly using extism_output_set.
func (wp *WASMPlugin) callStringFunction(functionName string) (string, error) {
	exitCode, resultBytes, err := wp.plugin.Call(functionName, nil)
	if err != nil {
		return "", fmt.Errorf("failed to call function %s: %w", functionName, err)
	}
	if exitCode != 0 {
		return "", fmt.Errorf("function %s returned non-zero exit code: %d", functionName, exitCode)
	}

	// Extism's Call() returns the output bytes directly (set via extism_output_set)
	if len(resultBytes) == 0 {
		return "", nil
	}

	return string(resultBytes), nil
}

// TCP connection management - store connections by ID
var (
	tcpConnections        = make(map[uint32]*net.TCPConn)
	tcpConnID      uint32 = 1
)

// newTCPConnectFunction creates a host function for TCP connections.
// WASM signature: (param i64) (result i32) - takes address offset, returns connection ID
func newTCPConnectFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"tcp_connect",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			// Read address string from plugin memory (offset is i64 in stack[0])
			addrOffset := stack[0]
			addr, err := p.ReadString(addrOffset)
			if err != nil {
				stack[0] = 0 // Return 0 on error (invalid connection ID)
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_connect: failed to read address: %v", err))
				return
			}

			// Establish TCP connection
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				stack[0] = 0 // Return 0 on error
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_connect: failed to connect to %s: %v", addr, err))
				return
			}

			// Store connection and return ID
			tcpConnID++
			connID := tcpConnID
			tcpConnections[connID] = conn.(*net.TCPConn)
			stack[0] = uint64(connID)
			p.Log(extism.LogLevelInfo, fmt.Sprintf("tcp_connect: connected to %s (conn_id=%d)", addr, connID))
		},
		[]extism.ValueType{extism.ValueTypeI64}, // addr_offset: i64
		[]extism.ValueType{extism.ValueTypeI32}, // conn_id: i32
	)
	fn.SetNamespace("env")
	return fn
}

// newTCPSendFunction creates a host function for sending data over TCP.
// WASM signature: (param i32 i64 i64) (result i32) - conn_id, data_offset, data_len -> bytes_sent
func newTCPSendFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"tcp_send",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			connID := uint32(stack[0]) // i32
			dataOffset := stack[1]     // i64
			dataLen := stack[2]        // i64

			// Get connection
			conn, ok := tcpConnections[connID]
			if !ok {
				stack[0] = 0 // Return 0 bytes sent on error
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_send: invalid connection ID %d", connID))
				return
			}

			// Read data from plugin memory
			data, err := p.ReadBytes(dataOffset)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_send: failed to read data: %v", err))
				return
			}

			// Limit to requested length
			if uint64(len(data)) > dataLen {
				data = data[:dataLen]
			}

			// Send data
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			bytesSent, err := conn.Write(data)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_send: failed to send data: %v", err))
				return
			}

			stack[0] = uint64(bytesSent)
			p.Log(extism.LogLevelInfo, fmt.Sprintf("tcp_send: sent %d bytes on conn_id=%d", bytesSent, connID))
		},
		[]extism.ValueType{extism.ValueTypeI32, extism.ValueTypeI64, extism.ValueTypeI64}, // conn_id, data_offset, data_len
		[]extism.ValueType{extism.ValueTypeI32},                                           // bytes_sent: i32
	)
	fn.SetNamespace("env")
	return fn
}

// newTCPRecvFunction creates a host function for receiving data over TCP.
// WASM signature: (param i32 i32) (result i64) - conn_id, max_len -> data_offset
func newTCPRecvFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"tcp_recv",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			connID := uint32(stack[0]) // i32
			maxLen := uint32(stack[1]) // i32

			// Get connection
			conn, ok := tcpConnections[connID]
			if !ok {
				stack[0] = 0 // Return 0 (invalid offset) on error
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_recv: invalid connection ID %d", connID))
				return
			}

			// Read data with timeout
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, maxLen)
			bytesRead, err := conn.Read(buf)
			if err != nil {
				// Check if it's a timeout (which might be expected)
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout is not necessarily an error - return empty data
					stack[0] = 0
					return
				}
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_recv: failed to receive data: %v", err))
				return
			}

			// Write received data to plugin memory
			dataOffset, err := p.WriteBytes(buf[:bytesRead])
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("tcp_recv: failed to write data to plugin memory: %v", err))
				return
			}

			stack[0] = dataOffset // Return i64 offset
			p.Log(extism.LogLevelInfo, fmt.Sprintf("tcp_recv: received %d bytes on conn_id=%d", bytesRead, connID))
		},
		[]extism.ValueType{extism.ValueTypeI32, extism.ValueTypeI32}, // conn_id, max_len: both i32
		[]extism.ValueType{extism.ValueTypeI64},                      // data_offset: i64
	)
	fn.SetNamespace("env")
	return fn
}

// newTCPCloseFunction creates a host function for closing TCP connections.
// WASM signature: (param i32) -> void - takes conn_id, returns nothing
func newTCPCloseFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"tcp_close",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			connID := uint32(stack[0]) // i32

			// Get and close connection
			conn, ok := tcpConnections[connID]
			if !ok {
				p.Log(extism.LogLevelWarn, fmt.Sprintf("tcp_close: invalid connection ID %d", connID))
				return
			}

			conn.Close()
			delete(tcpConnections, connID)
			p.Log(extism.LogLevelInfo, fmt.Sprintf("tcp_close: closed conn_id=%d", connID))
		},
		[]extism.ValueType{extism.ValueTypeI32}, // conn_id: i32
		[]extism.ValueType{},                    // void
	)
	fn.SetNamespace("env")
	return fn
}

// UDP connection management - store connections by ID
var (
	udpConnections        = make(map[uint32]*net.UDPConn)
	udpConnID      uint32 = 1
)

// newUDPConnectFunction creates a host function for UDP connections.
// WASM signature: (param i64) (result i32) - takes address offset, returns connection ID
func newUDPConnectFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"udp_connect",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			// Read address string from plugin memory (offset is i64 in stack[0])
			addrOffset := stack[0]
			addr, err := p.ReadString(addrOffset)
			if err != nil {
				stack[0] = 0 // Return 0 on error (invalid connection ID)
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_connect: failed to read address: %v", err))
				return
			}

			// Establish UDP connection
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				stack[0] = 0 // Return 0 on error
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_connect: failed to resolve address %s: %v", addr, err))
				return
			}

			conn, err := net.DialUDP("udp", nil, udpAddr)
			if err != nil {
				stack[0] = 0 // Return 0 on error
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_connect: failed to connect to %s: %v", addr, err))
				return
			}

			// Store connection and return ID
			udpConnID++
			connID := udpConnID
			udpConnections[connID] = conn
			stack[0] = uint64(connID)
			p.Log(extism.LogLevelInfo, fmt.Sprintf("udp_connect: connected to %s (conn_id=%d)", addr, connID))
		},
		[]extism.ValueType{extism.ValueTypeI64}, // addr_offset: i64
		[]extism.ValueType{extism.ValueTypeI32}, // conn_id: i32
	)
	fn.SetNamespace("env")
	return fn
}

// newUDPSendFunction creates a host function for sending data over UDP.
// WASM signature: (param i32 i64 i64) (result i32) - conn_id, data_offset, data_len -> bytes_sent
func newUDPSendFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"udp_send",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			connID := uint32(stack[0]) // i32
			dataOffset := stack[1]     // i64
			dataLen := stack[2]        // i64

			// Get connection
			conn, ok := udpConnections[connID]
			if !ok {
				stack[0] = 0 // Return 0 bytes sent on error
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_send: invalid connection ID %d", connID))
				return
			}

			// Read data from plugin memory
			data, err := p.ReadBytes(dataOffset)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_send: failed to read data: %v", err))
				return
			}

			// Limit to requested length
			if uint64(len(data)) > dataLen {
				data = data[:dataLen]
			}

			// Send data
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			bytesSent, err := conn.Write(data)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_send: failed to send data: %v", err))
				return
			}

			stack[0] = uint64(bytesSent)
			p.Log(extism.LogLevelInfo, fmt.Sprintf("udp_send: sent %d bytes on conn_id=%d", bytesSent, connID))
		},
		[]extism.ValueType{extism.ValueTypeI32, extism.ValueTypeI64, extism.ValueTypeI64}, // conn_id, data_offset, data_len
		[]extism.ValueType{extism.ValueTypeI32},                                           // bytes_sent: i32
	)
	fn.SetNamespace("env")
	return fn
}

// newUDPRecvFunction creates a host function for receiving data over UDP.
// WASM signature: (param i32 i32) (result i64) - conn_id, max_len -> data_offset
func newUDPRecvFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"udp_recv",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			connID := uint32(stack[0]) // i32
			maxLen := uint32(stack[1]) // i32

			// Get connection
			conn, ok := udpConnections[connID]
			if !ok {
				stack[0] = 0 // Return 0 (invalid offset) on error
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_recv: invalid connection ID %d", connID))
				return
			}

			// Read data with timeout
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, maxLen)
			bytesRead, err := conn.Read(buf)
			if err != nil {
				// Check if it's a timeout (which might be expected)
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Timeout is not necessarily an error - return empty data
					stack[0] = 0
					return
				}
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_recv: failed to receive data: %v", err))
				return
			}

			// Write received data to plugin memory
			dataOffset, err := p.WriteBytes(buf[:bytesRead])
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("udp_recv: failed to write data to plugin memory: %v", err))
				return
			}

			stack[0] = dataOffset // Return i64 offset
			p.Log(extism.LogLevelInfo, fmt.Sprintf("udp_recv: received %d bytes on conn_id=%d", bytesRead, connID))
		},
		[]extism.ValueType{extism.ValueTypeI32, extism.ValueTypeI32}, // conn_id, max_len: both i32
		[]extism.ValueType{extism.ValueTypeI64},                      // data_offset: i64
	)
	fn.SetNamespace("env")
	return fn
}

// newUDPCloseFunction creates a host function for closing UDP connections.
// WASM signature: (param i32) -> void - takes conn_id, returns nothing
func newUDPCloseFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"udp_close",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			connID := uint32(stack[0]) // i32

			// Get and close connection
			conn, ok := udpConnections[connID]
			if !ok {
				p.Log(extism.LogLevelWarn, fmt.Sprintf("udp_close: invalid connection ID %d", connID))
				return
			}

			conn.Close()
			delete(udpConnections, connID)
			p.Log(extism.LogLevelInfo, fmt.Sprintf("udp_close: closed conn_id=%d", connID))
		},
		[]extism.ValueType{extism.ValueTypeI32}, // conn_id: i32
		[]extism.ValueType{},                    // void
	)
	fn.SetNamespace("env")
	return fn
}

// newICMPSendFunction creates a host function for sending ICMP packets.
// WASM signature: (param i64 i64 i64 i32) (result i32) - target_offset, payload_offset, payload_len, seq -> success
func newICMPSendFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"icmp_send",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			targetOffset := stack[0]     // i64
			payloadOffset := stack[1]    // i64
			payloadLen := stack[2]       // i64
			seq := uint16(stack[3])     // i32 (as u16)

			// Read target address from plugin memory
			target, err := p.ReadString(targetOffset)
			if err != nil {
				stack[0] = 0 // Return 0 on error
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_send: failed to read target: %v", err))
				return
			}

			// Read payload from plugin memory
			payload, err := p.ReadBytes(payloadOffset)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_send: failed to read payload: %v", err))
				return
			}

			// Limit to requested length
			if uint64(len(payload)) > payloadLen {
				payload = payload[:payloadLen]
			}

			// Resolve target IP address
			ipAddr, err := net.ResolveIPAddr("ip", target)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_send: failed to resolve target %s: %v", target, err))
				return
			}

			// Create ICMP packet
			// ICMP Echo Request: Type 8, Code 0
			icmpMsg := &icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   1,
					Seq:  int(seq),
					Data: payload,
				},
			}

			// Marshal ICMP message
			icmpBytes, err := icmpMsg.Marshal(nil)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_send: failed to marshal ICMP message: %v", err))
				return
			}

			// Send ICMP packet
			conn, err := net.DialIP("ip4:icmp", nil, ipAddr)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_send: failed to dial ICMP: %v", err))
				return
			}
			defer conn.Close()

			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write(icmpBytes)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_send: failed to send ICMP packet: %v", err))
				return
			}

			stack[0] = 1 // Return 1 on success
			p.Log(extism.LogLevelInfo, fmt.Sprintf("icmp_send: sent ICMP packet to %s (seq=%d, payload_len=%d)", target, seq, len(payload)))
		},
		[]extism.ValueType{extism.ValueTypeI64, extism.ValueTypeI64, extism.ValueTypeI64, extism.ValueTypeI32}, // target_offset, payload_offset, payload_len, seq
		[]extism.ValueType{extism.ValueTypeI32}, // success: i32 (1 or 0)
	)
	fn.SetNamespace("env")
	return fn
}

// newICMPRecvFunction creates a host function for receiving ICMP packets.
// WASM signature: (param i32) (result i64) - timeout_ms -> json_offset
func newICMPRecvFunction() extism.HostFunction {
	fn := extism.NewHostFunctionWithStack(
		"icmp_recv",
		func(ctx context.Context, p *extism.CurrentPlugin, stack []uint64) {
			timeoutMs := uint32(stack[0]) // i32

			// Create a raw ICMP socket to receive packets
			conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_recv: failed to listen: %v", err))
				return
			}
			defer conn.Close()

			// Set read deadline
			timeout := time.Duration(timeoutMs) * time.Millisecond
			conn.SetReadDeadline(time.Now().Add(timeout))

			// Read ICMP packet
			buf := make([]byte, 1500)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				// Check if it's a timeout (which might be expected)
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					stack[0] = 0
					return
				}
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_recv: failed to receive: %v", err))
				return
			}

			// Parse ICMP message (protocol 1 = ICMP)
			msg, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_recv: failed to parse ICMP message: %v", err))
				return
			}

			// Build JSON response
			icmpType := 0
			if t, ok := msg.Type.(ipv4.ICMPType); ok {
				icmpType = int(t)
			}
			response := map[string]interface{}{
				"source": addr.String(),
				"type":   icmpType,
				"code":   msg.Code,
			}

			// Extract payload if it's an echo reply
			if echo, ok := msg.Body.(*icmp.Echo); ok {
				response["id"] = echo.ID
				response["seq"] = echo.Seq
				response["data"] = echo.Data
			} else {
				// For other ICMP types, include raw body data if available
				response["data"] = []byte{}
			}

			// Marshal to JSON
			jsonBytes, err := json.Marshal(response)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_recv: failed to marshal JSON: %v", err))
				return
			}

			// Write JSON to plugin memory
			jsonOffset, err := p.WriteBytes(jsonBytes)
			if err != nil {
				stack[0] = 0
				p.Log(extism.LogLevelError, fmt.Sprintf("icmp_recv: failed to write JSON to plugin memory: %v", err))
				return
			}

			stack[0] = jsonOffset // Return i64 offset
			p.Log(extism.LogLevelInfo, fmt.Sprintf("icmp_recv: received ICMP packet from %s (type=%d, code=%d)", addr, msg.Type, msg.Code))
		},
		[]extism.ValueType{extism.ValueTypeI32}, // timeout_ms: i32
		[]extism.ValueType{extism.ValueTypeI64}, // json_offset: i64
	)
	fn.SetNamespace("env")
	return fn
}
