# ALTCP (Application Layered TCP) - Detailed Explanation

## What is ALTCP?

**ALTCP** (Application Layered TCP) is an **optional abstraction layer** in LwIP that sits between applications and the TCP stack. It provides a plugin architecture for adding protocol layers on top of TCP without modifying application code.

**File:** `src/core/altcp.c:16-21`

> altcp (application layered TCP connection API; to be used from TCPIP thread) is an abstraction layer that prevents applications linking hard against the tcp.h functions while providing the same functionality. It is used to e.g. add SSL/TLS (see LWIP_ALTCP_TLS) or proxy-connect support to an application written for the tcp callback API without that application knowing the protocol details.

---

## Key Concept: Virtual Function Table (Vtable)

ALTCP uses a **C-style vtable pattern** to implement polymorphism, similar to C++ virtual functions but manually implemented:

```c
struct altcp_pcb {
  const struct altcp_functions *fns;  // ← Vtable pointer at offset 0
  struct altcp_pcb *inner_conn;       // For layering (e.g., TLS → TCP)
  void *arg;                           // Application argument
  void *state;                         // Implementation-specific state
  // Application callbacks
  altcp_accept_fn     accept;
  altcp_connected_fn  connected;
  altcp_recv_fn       recv;
  altcp_sent_fn       sent;
  altcp_poll_fn       poll;
  altcp_err_fn        err;
  u8_t pollinterval;
};
```

The vtable contains 20+ function pointers for all TCP operations:

```c
struct altcp_functions {
  altcp_set_poll_fn           set_poll;
  altcp_recved_fn             recved;
  altcp_bind_fn               bind;
  altcp_connect_fn            connect;
  altcp_listen_fn             listen;
  altcp_abort_fn              abort;
  altcp_close_fn              close;
  altcp_shutdown_fn           shutdown;
  altcp_write_fn              write;
  altcp_output_fn             output;
  altcp_mss_fn                mss;
  altcp_sndbuf_fn             sndbuf;
  altcp_sndqueuelen_fn        sndqueuelen;
  altcp_nagle_disable_fn      nagle_disable;
  altcp_nagle_enable_fn       nagle_enable;
  altcp_nagle_disabled_fn     nagle_disabled;
  altcp_setprio_fn            setprio;
  altcp_dealloc_fn            dealloc;
  altcp_get_tcp_addrinfo_fn   addrinfo;
  altcp_get_ip_fn             getip;
  altcp_get_port_fn           getport;
  // Optional keepalive and debug functions...
};
```

---

## When is ALTCP Active?

### Configuration Flag

**File:** `src/lwip/opt.h:1494-1496`

```c
#if !defined LWIP_ALTCP || defined __DOXYGEN__
#define LWIP_ALTCP                      0  // ← DEFAULT: DISABLED
#endif
```

**Default: ALTCP is DISABLED (`LWIP_ALTCP=0`)**

### When LWIP_ALTCP=0 (Default)

When ALTCP is disabled, all ALTCP functions are **preprocessor macros** that redirect to standard TCP functions:

**File:** `src/lwip/altcp.h:145-204`

```c
#else /* LWIP_ALTCP */

/* ALTCP disabled, define everything to link against tcp callback API */

#define altcp_pcb tcp_pcb               // ← altcp_pcb IS tcp_pcb
#define altcp_new(allocator) tcp_new()  // ← Just calls tcp_new()
#define altcp_write tcp_write
#define altcp_close tcp_close
// ... all other functions are macros ...

#endif /* LWIP_ALTCP */
```

**Result:**
- No vtable pointer exists
- No extra memory allocated
- Direct function calls to TCP stack
- Zero overhead
- **No security risk from vtable corruption**

### When LWIP_ALTCP=1 (Explicitly Enabled)

Applications must define in their `lwipopts.h`:

```c
#define LWIP_ALTCP 1
```

**Result:**
- `altcp_pcb` is a real structure with vtable pointer at offset 0
- Extra memory allocation for each connection
- Indirect function calls through vtable
- **Vtable corruption vulnerability exists**

---

## When is altcp_pcb Allocated?

### 1. Application Creates TCP Connection

**Without allocator (plain TCP):**

```c
struct altcp_pcb *conn = altcp_new(NULL);
```

**Call chain:**
```
altcp_new(NULL)
  ↓
altcp_new_ip_type(NULL, IPADDR_TYPE_V4)  [altcp.c:189]
  ↓
altcp_tcp_new_ip_type(IPADDR_TYPE_V4)    [altcp_tcp.c:194]
  ↓
tcp_new_ip_type(IPADDR_TYPE_V4)          [allocates tcp_pcb]
  ↓
altcp_alloc()                             [altcp.c:136]
  ↓
memp_malloc(MEMP_ALTCP_PCB)              [allocates altcp_pcb]
  ↓
altcp_tcp_setup(ret, tpcb)               [altcp_tcp.c:186]
  ↓
conn->fns = &altcp_tcp_functions         [altcp_tcp.c:190] ← VTABLE SET
```

**File:** `src/core/altcp_tcp.c:194-210`

```c
struct altcp_pcb *
altcp_tcp_new_ip_type(u8_t ip_type)
{
  // Allocate TCP PCB first
  struct tcp_pcb *tpcb = tcp_new_ip_type(ip_type);
  if (tpcb != NULL) {
    // Allocate ALTCP wrapper
    struct altcp_pcb *ret = altcp_alloc();
    if (ret != NULL) {
      altcp_tcp_setup(ret, tpcb);  // Sets vtable and state
      return ret;
    } else {
      tcp_close(tpcb);  // Cleanup on failure
    }
  }
  return NULL;
}
```

**File:** `src/core/altcp_tcp.c:186-191`

```c
static void
altcp_tcp_setup(struct altcp_pcb *conn, struct tcp_pcb *tpcb)
{
  altcp_tcp_setup_callbacks(conn, tpcb);
  conn->state = tpcb;                      // Points to underlying tcp_pcb
  conn->fns = &altcp_tcp_functions;        // ← VTABLE POINTER SET HERE
}
```

**File:** `src/core/altcp.c:136-143`

```c
struct altcp_pcb *
altcp_alloc(void)
{
  struct altcp_pcb *ret = (struct altcp_pcb *)memp_malloc(MEMP_ALTCP_PCB);
  if (ret != NULL) {
    memset(ret, 0, sizeof(struct altcp_pcb));  // Zero all fields
  }
  return ret;
}
```

### 2. Application Creates TLS Connection

**With TLS allocator:**

```c
// Setup TLS config
struct altcp_tls_config *conf = altcp_tls_create_config_client(cert, sizeof(cert));

// Create allocator
altcp_allocator_t tls_allocator = {
  .alloc = altcp_tls_alloc,
  .arg = conf
};

// Create TLS connection
struct altcp_pcb *conn = altcp_new(&tls_allocator);
```

**Call chain:**
```
altcp_new(&tls_allocator)
  ↓
altcp_new_ip_type(&tls_allocator, IPADDR_TYPE_V4)
  ↓
tls_allocator.alloc(conf, IPADDR_TYPE_V4)  // Calls altcp_tls_alloc()
  ↓
[TLS implementation allocates altcp_pcb]
  ↓
conn->fns = &altcp_tls_functions           ← TLS VTABLE SET
conn->inner_conn = altcp_tcp_new()         ← Layered over TCP
```

**Layering structure:**
```
[Application]
     ↓
[altcp_pcb (TLS layer)]
 - fns → &altcp_tls_functions
 - inner_conn → [altcp_pcb (TCP layer)]
                 - fns → &altcp_tcp_functions
                 - state → tcp_pcb
```

### 3. Incoming Connection on Listening Socket

**File:** `src/core/altcp_tcp.c:73-87`

```c
static err_t
altcp_tcp_accept(void *arg, struct tcp_pcb *new_tpcb, err_t err)
{
  struct altcp_pcb *listen_conn = (struct altcp_pcb *)arg;
  if (listen_conn && listen_conn->accept) {
    // Create a new altcp_pcb for the accepted connection
    struct altcp_pcb *new_conn = altcp_alloc();  // ← ALLOCATED HERE
    if (new_conn == NULL) {
      return ERR_MEM;
    }
    altcp_tcp_setup(new_conn, new_tpcb);  // Sets vtable
    return listen_conn->accept(listen_conn->arg, new_conn, err);
  }
  return ERR_ARG;
}
```

**When:** Every time a new TCP connection is accepted on a listening ALTCP socket.

---

## Use Cases for ALTCP

### 1. SSL/TLS Support

**Primary use case:** Add TLS encryption to HTTP servers/clients without changing application code.

**Example: HTTPS Server**

```c
// Without ALTCP (HTTP only):
struct tcp_pcb *pcb = tcp_new();
tcp_bind(pcb, IP_ADDR_ANY, 80);
pcb = tcp_listen(pcb);
tcp_accept(pcb, http_accept_callback);

// With ALTCP (HTTP or HTTPS):
struct altcp_pcb *pcb = altcp_new(&tls_allocator);  // TLS if allocator set
altcp_bind(pcb, IP_ADDR_ANY, 443);
pcb = altcp_listen(pcb);
altcp_accept(pcb, http_accept_callback);  // Same callback!
```

### 2. Proxy Support

**Use case:** Connect through HTTP CONNECT proxy transparently.

```c
altcp_allocator_t proxy_allocator = {
  .alloc = altcp_proxyconnect_alloc,
  .arg = proxy_config
};

struct altcp_pcb *conn = altcp_new(&proxy_allocator);
altcp_connect(conn, target_ip, target_port, connected_callback);
// Proxy negotiation happens transparently
```

### 3. Protocol Testing/Monitoring

**Use case:** Insert a monitoring layer to log all TCP traffic.

```c
// Custom monitoring layer
struct altcp_functions monitor_functions = {
  .write = monitor_write,  // Logs data before calling real write
  .recv = monitor_recv,    // Logs received data
  // ... other functions wrap underlying layer
};
```

---

## Real-World Deployment Scenarios

### Scenario A: Embedded Device (No TLS) - ALTCP Disabled

**Configuration:**
```c
// lwipopts.h
#define LWIP_ALTCP 0  // Default
```

**Result:**
- No `altcp_pcb` structures allocated
- No vtable pointers
- Application uses `tcp_pcb` directly
- **No vtable vulnerability**

**Common in:**
- Simple IoT devices
- Devices using pre-shared keys or no encryption
- Memory-constrained systems

### Scenario B: Web Server with Optional TLS - ALTCP Enabled

**Configuration:**
```c
// lwipopts.h
#define LWIP_ALTCP 1
#define LWIP_ALTCP_TLS 1
```

**Result:**
- Every connection allocates `altcp_pcb`
- Vtable pointer set to `&altcp_tcp_functions` or `&altcp_tls_functions`
- **Vtable vulnerability exists**

**Common in:**
- HTTPS web servers
- MQTT over TLS
- Secure firmware update mechanisms
- Any application requiring TLS

---

## Memory Overhead

### Per Connection (LWIP_ALTCP=1)

```
Standard TCP connection:
  tcp_pcb: ~400 bytes

ALTCP Plain TCP connection:
  altcp_pcb: ~40-60 bytes
  tcp_pcb: ~400 bytes
  Total: ~450 bytes (12.5% overhead)

ALTCP TLS connection:
  altcp_pcb (TLS layer): ~40-60 bytes
  altcp_pcb (TCP layer): ~40-60 bytes
  tcp_pcb: ~400 bytes
  TLS state (mbedTLS): ~15-30 KB
  Total: ~16-30 KB
```

---

## Security Implications Summary

### When ALTCP is Disabled (Default)

✅ **No vtable vulnerability**
- `altcp_pcb` is just a macro for `tcp_pcb`
- No function pointer at offset 0
- Direct function calls

### When ALTCP is Enabled

⚠️ **Vtable vulnerability exists**
- `altcp_pcb` structure allocated for every connection
- Vtable pointer at offset 0
- Corruption leads to arbitrary code execution

**Attack scenarios:**
1. Overflow from adjacent pbuf payload
2. Heap corruption via pool management bugs
3. Use-after-free if altcp_pcb freed but still referenced

**Mitigation:**
- Only enable ALTCP when TLS or proxy support is needed
- Enable compiler CFI (Control Flow Integrity)
- Validate vtable pointer before use
- Use memory protection (ASLR, DEP)

---

## Configuration Check

### How to Tell if ALTCP is Enabled in Your Build

**Method 1: Check lwipopts.h**
```c
grep LWIP_ALTCP lwipopts.h
```

**Method 2: Check compiled binary**
```bash
# Look for altcp symbols
nm firmware.elf | grep altcp_alloc
# If found: ALTCP is enabled
# If not found: ALTCP is disabled
```

**Method 3: Runtime check (if debug enabled)**
```c
#if LWIP_ALTCP
  printf("ALTCP is ENABLED\n");
#else
  printf("ALTCP is DISABLED\n");
#endif
```

---

## Vtable Initialization and Contents

### For Plain TCP Connections

**File:** `src/core/altcp_tcp.c` (end of file)

```c
const struct altcp_functions altcp_tcp_functions = {
  altcp_tcp_set_poll,
  altcp_tcp_recved,
  altcp_tcp_bind,
  altcp_tcp_connect,
  altcp_tcp_listen,
  altcp_tcp_abort,
  altcp_tcp_close,
  altcp_tcp_shutdown,
  altcp_tcp_write,
  altcp_tcp_output,
  altcp_tcp_mss,
  altcp_tcp_sndbuf,
  altcp_tcp_sndqueuelen,
  altcp_tcp_nagle_disable,
  altcp_tcp_nagle_enable,
  altcp_tcp_nagle_disabled,
  altcp_tcp_setprio,
  altcp_tcp_dealloc,
  altcp_tcp_get_tcp_addrinfo,
  altcp_tcp_get_ip,
  altcp_tcp_get_port,
#if LWIP_TCP_KEEPALIVE
  altcp_tcp_keepalive_disable,
  altcp_tcp_keepalive_enable,
#endif
#ifdef LWIP_DEBUG
  altcp_tcp_dbg_get_tcp_state
#endif
};
```

**Set by:** `conn->fns = &altcp_tcp_functions;` in `altcp_tcp_setup()` (altcp_tcp.c:190)

### For TLS Connections

**File:** `src/apps/altcp_tls/altcp_tls_mbedtls.c` (if using mbedTLS port)

```c
const struct altcp_functions altcp_tls_functions = {
  altcp_tls_set_poll,
  altcp_tls_recved,
  altcp_tls_bind,
  altcp_tls_connect,
  altcp_tls_listen,
  altcp_tls_abort,
  altcp_tls_close,
  altcp_tls_shutdown,
  altcp_tls_write,      // ← Encrypts data before sending
  altcp_tls_output,
  altcp_tls_mss,
  // ... other TLS-specific implementations
};
```

---

## Code Flow Example: Writing Data

### Application Code

```c
altcp_write(conn, "GET / HTTP/1.1\r\n", 16, TCP_WRITE_FLAG_COPY);
```

### With LWIP_ALTCP=1 (Plain TCP)

**File:** `src/core/altcp.c`

```c
err_t altcp_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
  if (conn && conn->fns && conn->fns->write) {
    return conn->fns->write(conn, dataptr, len, apiflags);  // ← Indirect call
    //     ^                  ^
    //     |                  |
    //  Vtable pointer     Function pointer in vtable
  }
  return ERR_VAL;
}
```

**Resolves to:** `altcp_tcp_write()` → `tcp_write()`

### With LWIP_ALTCP=1 (TLS)

**Resolves to:** `altcp_tls_write()` → encrypts data → `altcp_write(inner_conn)` → `altcp_tcp_write()` → `tcp_write()`

### With LWIP_ALTCP=0

**Macro expansion:**
```c
#define altcp_write tcp_write

// Becomes:
tcp_write(conn, "GET / HTTP/1.1\r\n", 16, TCP_WRITE_FLAG_COPY);
// ← Direct call, no indirection, no vtable
```

---

## Conclusion

**ALTCP is:**
- An **optional** abstraction layer (disabled by default)
- Used primarily for **TLS/SSL** and **proxy** support
- Implements **vtable pattern** for polymorphism in C
- **Only a security concern when explicitly enabled** (`LWIP_ALTCP=1`)
- **Not used** in simple embedded deployments without TLS

**The vtable vulnerability:**
- **Does not exist** in default configurations (LWIP_ALTCP=0)
- **Only exists** when ALTCP is explicitly enabled for TLS/proxy support
- **Is a real concern** for web servers, HTTPS clients, and secure IoT devices

**When evaluating security:**
1. Check if `LWIP_ALTCP=1` in your configuration
2. If disabled: vtable vulnerability does not apply
3. If enabled: implement protections (CFI, pointer validation, memory safety)
