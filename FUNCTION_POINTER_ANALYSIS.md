# LwIP Function Pointer Analysis
## Heap-Allocated Structures with Function Pointers

**Analysis Date:** 2025-11-19
**Purpose:** Identify heap-allocated structures containing function pointers, particularly those near the start of the structure (potential security implications).

---

## Executive Summary

**CRITICAL FINDING:** The `altcp_pcb` structure contains a **vtable pointer at offset 0**, making it a high-value target for memory corruption exploits.

This analysis identified 9 structures in LwIP containing function pointers. Of these, **only one has a function pointer table at offset 0**, but several others have function pointers at relatively low offsets.

---

## 1. ALTCP_PCB - CRITICAL (Vtable at Offset 0)

### Structure Definition
**File:** `/home/user/LwIP/src/lwip/altcp.h:68-81`

```c
struct altcp_pcb {
  const struct altcp_functions *fns;  // ← OFFSET 0: Vtable pointer
  struct altcp_pcb *inner_conn;       // Offset ~4-8
  void *arg;                           // Offset ~8-16
  void *state;                         // Offset ~12-24
  /* Application callbacks */
  altcp_accept_fn     accept;          // Function pointer
  altcp_connected_fn  connected;       // Function pointer
  altcp_recv_fn       recv;            // Function pointer
  altcp_sent_fn       sent;            // Function pointer
  altcp_poll_fn       poll;            // Function pointer
  altcp_err_fn        err;             // Function pointer
  u8_t pollinterval;
};
```

### The Vtable (altcp_functions)
**File:** `/home/user/LwIP/src/lwip/priv/altcp_priv.h:97-126`

The vtable contains **20+ function pointers**:

```c
struct altcp_functions {
  altcp_set_poll_fn           set_poll;         // Offset 0
  altcp_recved_fn             recved;           // Offset ~4-8
  altcp_bind_fn               bind;             // Offset ~8-16
  altcp_connect_fn            connect;          // Function pointer
  altcp_listen_fn             listen;           // Function pointer
  altcp_abort_fn              abort;            // Function pointer
  altcp_close_fn              close;            // Function pointer
  altcp_shutdown_fn           shutdown;         // Function pointer
  altcp_write_fn              write;            // Function pointer
  altcp_output_fn             output;           // Function pointer
  altcp_mss_fn                mss;              // Function pointer
  altcp_sndbuf_fn             sndbuf;           // Function pointer
  altcp_sndqueuelen_fn        sndqueuelen;      // Function pointer
  altcp_nagle_disable_fn      nagle_disable;    // Function pointer
  altcp_nagle_enable_fn       nagle_enable;     // Function pointer
  altcp_nagle_disabled_fn     nagle_disabled;   // Function pointer
  altcp_setprio_fn            setprio;          // Function pointer
  altcp_dealloc_fn            dealloc;          // Function pointer
  altcp_get_tcp_addrinfo_fn   addrinfo;         // Function pointer
  altcp_get_ip_fn             getip;            // Function pointer
  altcp_get_port_fn           getport;          // Function pointer
#if LWIP_TCP_KEEPALIVE
  altcp_keepalive_disable_fn  keepalive_disable;
  altcp_keepalive_enable_fn   keepalive_enable;
#endif
#ifdef LWIP_DEBUG
  altcp_dbg_get_tcp_state_fn  dbg_get_tcp_state;
#endif
};
```

### Allocation

**File:** `/home/user/LwIP/src/core/altcp.c:138`

```c
struct altcp_pcb *altcp_alloc(void)
{
  struct altcp_pcb *ret = (struct altcp_pcb *)memp_malloc(MEMP_ALTCP_PCB);
  if (ret != NULL) {
    memset(ret, 0, sizeof(struct altcp_pcb));
  }
  return ret;
}
```

**Allocation Method:**
- Uses `memp_malloc(MEMP_ALTCP_PCB)`
- If `MEMP_MEM_MALLOC` is enabled, this uses `mem_malloc()` (heap allocation)
- Otherwise, uses fixed-size memory pool

### Security Implications

**Exploit Scenario:**
1. Attacker corrupts `altcp_pcb` structure (e.g., via buffer overflow in adjacent pbuf payload)
2. Overwrites `fns` pointer at offset 0
3. Points to attacker-controlled memory containing fake vtable
4. When any altcp function is called (e.g., `altcp_write()`, `altcp_close()`), control flow is hijacked

**Example Attack:**
```c
// LwIP calls altcp_write()
// File: src/core/altcp.c
err_t altcp_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags)
{
  if (conn && conn->fns && conn->fns->write) {
    return conn->fns->write(conn, dataptr, len, apiflags);  // ← Hijacked!
  }
  return ERR_VAL;
}
```

If `conn->fns` points to attacker memory, `conn->fns->write` can be an arbitrary function pointer.

**Mitigation Present:**
- The `fns` pointer is `const struct altcp_functions *`, but this doesn't prevent modification via buffer overflow
- No CFI (Control Flow Integrity) or pointer authentication mentioned in code

---

## 2. PBUF_CUSTOM - Moderate Risk (Function Pointer at ~24 bytes)

### Structure Definition
**File:** `/home/user/LwIP/src/lwip/pbuf.h:245-250`

```c
struct pbuf_custom {
  struct pbuf pbuf;                         // ~24-32 bytes (platform dependent)
  pbuf_free_custom_fn custom_free_function; // ← Function pointer at offset ~24
};
```

### Base Structure (pbuf)
**File:** `/home/user/LwIP/src/lwip/pbuf.h:186-225`

```c
struct pbuf {
  struct pbuf *next;        // Offset 0 (4-8 bytes)
  void *payload;            // Offset 4-8 (4-8 bytes)
  u16_t tot_len;            // Offset 8-16
  u16_t len;                // Offset 10-18
  u8_t type_internal;       // Offset 12-20
  u8_t flags;               // Offset 13-21
  LWIP_PBUF_REF_T ref;      // Offset 14-22
  u8_t if_idx;              // Offset 15-23
  // Total: ~16-24 bytes depending on alignment
};
```

### Allocation

**IMPORTANT:** `pbuf_custom` is **NOT allocated by LwIP**. It's allocated by the application/driver and passed to:

**File:** `/home/user/LwIP/src/core/pbuf.c:362-382`

```c
struct pbuf *pbuf_alloced_custom(pbuf_layer l, u16_t length, pbuf_type type,
                                 struct pbuf_custom *p,  // ← Externally allocated!
                                 void *payload_mem, u16_t payload_mem_len)
{
  u16_t offset = (u16_t)l;
  void *payload;

  if (payload_mem != NULL) {
    payload = (u8_t *)payload_mem + LWIP_MEM_ALIGN_SIZE(offset);
  } else {
    payload = NULL;
  }

  pbuf_init_alloced_pbuf(&p->pbuf, payload, length, length, type,
                         PBUF_FLAG_IS_CUSTOM);

  return &p->pbuf;
}
```

### Usage

**File:** `/home/user/LwIP/src/core/pbuf.c:768-771`

```c
// In pbuf_free():
if ((p->flags & PBUF_FLAG_IS_CUSTOM) != 0) {
  struct pbuf_custom *pc = (struct pbuf_custom *)p;
  pc->custom_free_function(p);  // ← Function pointer call
}
```

### Security Implications

**Exploit Scenario:**
1. Application allocates `pbuf_custom` on heap
2. Attacker corrupts adjacent memory, overwriting `custom_free_function`
3. When `pbuf_free()` is called, arbitrary code execution

**Lower Risk Because:**
- Application controls allocation, not LwIP
- Function pointer at higher offset (~24 bytes)
- Requires corruption of application-allocated memory

---

## 3. TCP_PCB - Lower Risk (Callbacks at High Offset)

### Structure Definition
**File:** `/home/user/LwIP/src/lwip/tcp.h:242-389`

```c
struct tcp_pcb {
  /** common PCB members */
  IP_PCB;  // Expands to ip addresses, netif_idx, options, tos, ttl (~20-40 bytes)

  /** protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb);  // Expands to next, callback_arg, state, prio, local_port

  u16_t remote_port;
  tcpflags_t flags;

  // ... ~300 bytes of TCP state variables ...

  // Function pointers at HIGH offset (~350+ bytes):
  tcp_sent_fn sent;           // Application callback
  tcp_recv_fn recv;           // Application callback
  tcp_connected_fn connected; // Application callback
  tcp_poll_fn poll;           // Application callback
  tcp_err_fn errf;            // Application callback
};
```

### Macro Expansions

**IP_PCB** (File: `/home/user/LwIP/src/lwip/ip.h:76-89`):
```c
#define IP_PCB                             \
  ip_addr_t local_ip;    /* Offset 0 */    \
  ip_addr_t remote_ip;   /* ~20 bytes */   \
  u8_t netif_idx;                          \
  u8_t so_options;                         \
  u8_t tos;                                \
  u8_t ttl;                                \
  IP_PCB_NETIFHINT  /* Optional */
```

**TCP_PCB_COMMON** (File: `/home/user/LwIP/src/lwip/tcp.h:212-219`):
```c
#define TCP_PCB_COMMON(type) \
  type *next;                \
  void *callback_arg;        \  // Data pointer, not function pointer
  TCP_PCB_EXTARGS            \
  enum tcp_state state;      \
  u8_t prio;                 \
  u16_t local_port
```

### Allocation

**File:** `/home/user/LwIP/src/core/tcp.c:1841`

```c
pcb = (struct tcp_pcb *)memp_malloc(MEMP_TCP_PCB);
```

### Security Implications

**Lower Risk:**
- Function pointers at very high offset (350+ bytes)
- Requires large buffer overflow to reach callbacks
- Many critical TCP state variables before callbacks (corruption likely causes crash before exploit)

---

## 4. TCP_PCB_LISTEN - Moderate Risk (Callback at Medium Offset)

### Structure Definition
**File:** `/home/user/LwIP/src/lwip/tcp.h:223-238`

```c
struct tcp_pcb_listen {
  /** Common members of all PCB types */
  IP_PCB;                                   // ~20-40 bytes
  /** Protocol specific PCB members */
  TCP_PCB_COMMON(struct tcp_pcb_listen);    // ~20-30 bytes

#if LWIP_CALLBACK_API
  /* Function to call when a listener has been connected. */
  tcp_accept_fn accept;  // ← Function pointer at offset ~40-70 bytes
#endif

#if TCP_LISTEN_BACKLOG
  u8_t backlog;
  u8_t accepts_pending;
#endif
};
```

### Allocation

**File:** `/home/user/LwIP/src/core/tcp.c:883`

```c
lpcb = (struct tcp_pcb_listen *)memp_malloc(MEMP_TCP_PCB_LISTEN);
```

### Security Implications

**Moderate Risk:**
- Smaller structure than `tcp_pcb` (~50-80 bytes total)
- Function pointer at medium offset (~40-70 bytes)
- Single callback easier to target than multiple

---

## 5. UDP_PCB - Moderate Risk (Callback at Medium Offset)

### Structure Definition
**File:** `/home/user/LwIP/src/lwip/udp.h:81-113`

```c
struct udp_pcb {
  IP_PCB;  // ~20-40 bytes

  struct udp_pcb *next;

  u8_t flags;
  u16_t local_port, remote_port;

#if LWIP_MULTICAST_TX_OPTIONS
  u8_t mcast_ttl;
  u8_t mcast_ifindex;
#endif

#if LWIP_UDPLITE
  u16_t chksum_len_rx;
#endif

  udp_recv_fn recv;  // ← Function pointer at offset ~30-60 bytes
  void *recv_arg;
};
```

### Allocation

**File:** `/home/user/LwIP/src/core/udp.c:1229`

```c
pcb = (struct udp_pcb *)memp_malloc(MEMP_UDP_PCB);
```

### Security Implications

**Moderate Risk:**
- Small structure (~40-70 bytes)
- Single function pointer for receive callback
- Medium offset makes it reachable via moderate overflow

---

## 6. RAW_PCB - Moderate Risk

### Structure Definition
**File:** `/home/user/LwIP/src/lwip/raw.h:75-100`

```c
struct raw_pcb {
  IP_PCB;  // ~20-40 bytes

  struct raw_pcb *next;
  u8_t protocol;

#if LWIP_MULTICAST_TX_OPTIONS
  u8_t mcast_ttl;
  u8_t mcast_ifindex;
#endif

  raw_recv_fn recv;  // ← Function pointer at offset ~30-60 bytes
  void *recv_arg;

#if LWIP_IPV6
  u8_t chksum_reqd;
  u16_t chksum_offset;
#endif
};
```

### Allocation

**File:** Likely `memp_malloc(MEMP_RAW_PCB)` (pattern consistent with other PCBs)

---

## 7. Heap vs Pool Allocation

### Memory Pool System

**File:** `/home/user/LwIP/src/core/memp.c:243-260`

```c
static void *do_memp_malloc_pool(const struct memp_desc *desc)
{
  struct memp *memp;

#if MEMP_MEM_MALLOC
  // If enabled, use heap allocation
  memp = (struct memp *)mem_malloc(MEMP_SIZE + MEMP_ALIGN_SIZE(desc->size));
#else
  // Otherwise, use fixed-size pool
  memp = *desc->tab;
  if (memp != NULL) {
    *desc->tab = memp->next;  // Remove from free list
  }
#endif

  return (u8_t *)memp + MEMP_SIZE;
}
```

### Configuration-Dependent Heap Allocation

**If `MEMP_MEM_MALLOC` is enabled:**
- All `memp_malloc()` calls use heap (`mem_malloc()`)
- PCBs are heap-allocated
- Traditional heap exploitation techniques apply

**If `MEMP_MEM_MALLOC` is disabled (default):**
- PCBs allocated from fixed-size memory pools
- Predictable layout, but less heap spray flexibility
- Pool corruption still possible

---

## 8. PBUF_RAM - Heap Allocation

### Structure
Standard `pbuf` structure (see section 2), but payload is contiguous.

### Allocation

**File:** `/home/user/LwIP/src/core/pbuf.c:284`

```c
case PBUF_RAM: {
  mem_size_t alloc_len = LWIP_MEM_ALIGN_SIZE(SIZEOF_STRUCT_PBUF) +
                         LWIP_MEM_ALIGN_SIZE(offset) +
                         LWIP_MEM_ALIGN_SIZE(length);

  p = (struct pbuf *)mem_malloc(alloc_len);  // ← HEAP ALLOCATION

  if (p == NULL) {
    return NULL;
  }

  pbuf_init_alloced_pbuf(p,
    LWIP_MEM_ALIGN((void *)((u8_t *)p + SIZEOF_STRUCT_PBUF + offset)),
    length, length, type, 0);
}
```

### Memory Layout

```
[pbuf struct ~24 bytes] [offset padding] [payload data]
^                       ^
|                       |
p                       p->payload
```

### Security Implications

- **Always heap-allocated** via `mem_malloc()`
- No function pointers in base `pbuf` structure
- But adjacent to other heap objects that might contain function pointers
- Payload overflow could corrupt adjacent structures (e.g., `altcp_pcb`)

---

## Summary Table: Function Pointer Locations

| Structure | Function Pointer | Approx Offset | Allocation | Risk Level |
|-----------|------------------|---------------|------------|------------|
| **altcp_pcb** | **fns (vtable)** | **0 bytes** | **memp_malloc** | **CRITICAL** |
| pbuf_custom | custom_free_function | ~24 bytes | External | Moderate |
| tcp_pcb_listen | accept | ~40-70 bytes | memp_malloc | Moderate |
| udp_pcb | recv | ~30-60 bytes | memp_malloc | Moderate |
| raw_pcb | recv | ~30-60 bytes | memp_malloc | Moderate |
| tcp_pcb | sent/recv/poll/err | ~350+ bytes | memp_malloc | Low |

---

## Exploitation Considerations

### 1. Adjacent Memory Corruption

**Scenario:** Pbuf payload overflow into adjacent PCB

```
Heap Layout:
[PBUF_RAM allocation] [altcp_pcb allocation]
[pbuf struct|payload] [fns*|inner_conn|...]
              ↑               ↑
              |               |
          Overflow from here to here
```

**If payload buffer overflow occurs:**
- Attacker can overwrite `altcp_pcb.fns` pointer
- Next vtable call leads to arbitrary code execution

### 2. Pool Metadata Corruption

Even with pool allocation, metadata corruption possible:
- Corrupt pool free list pointers
- Cause allocation to return attacker-controlled address
- Next allocation overwrites critical data

### 3. Use-After-Free

**Scenario:**
1. PCB allocated and callbacks registered
2. PCB freed, returned to pool/heap
3. Attacker triggers reallocation with controlled data
4. Callback invoked on corrupted PCB

---

## Mitigation Recommendations

### Code-Level Mitigations

1. **Pointer Validation:**
   ```c
   // Before calling vtable function
   if (conn && conn->fns &&
       is_valid_vtable_ptr(conn->fns) &&  // ← Add validation
       conn->fns->write) {
     return conn->fns->write(conn, dataptr, len, apiflags);
   }
   ```

2. **Bounds Checking:**
   - Add strict bounds checking on pbuf operations
   - Validate payload writes don't exceed allocated size

3. **Memory Tagging:**
   - Tag function pointers with canary values
   - Validate before dereferencing

### Compiler/Platform Mitigations

1. **CFI (Control Flow Integrity):**
   - Modern compilers support CFI to prevent vtable hijacking
   - `-fsanitize=cfi` (Clang) or similar

2. **Pointer Authentication (ARM PAC):**
   - Sign function pointers when stored
   - Verify before use

3. **ASLR (Address Space Layout Randomization):**
   - Randomize heap addresses
   - Makes exploitation harder but not impossible

4. **Stack Canaries:**
   - Protect against buffer overflows reaching function pointers

---

## Detection Strategies

### Runtime Detection

1. **Integrity Checks:**
   ```c
   #define VALIDATE_VTABLE(pcb) \
     LWIP_ASSERT("valid vtable", \
       (pcb)->fns == &altcp_tcp_functions || \
       (pcb)->fns == &altcp_tls_functions)
   ```

2. **Pool Corruption Detection:**
   - Add magic numbers to pool entries
   - Validate on allocation/deallocation

3. **Reference Counting Audits:**
   - Track PCB reference counts
   - Detect use-after-free attempts

### Static Analysis

1. **Fuzzing:**
   - Fuzz pbuf operations with ASAN/MSAN
   - Detect buffer overflows before deployment

2. **Code Auditing:**
   - Review all pbuf payload writes
   - Ensure bounds checking

---

## Conclusion

**CRITICAL VULNERABILITY PATTERN IDENTIFIED:**

The `altcp_pcb` structure with its vtable pointer at offset 0 presents a **high-value target** for memory corruption exploits. Combined with the pbuf payload reuse scenarios documented in `PBUF_PAYLOAD_REUSE_ANALYSIS.md`, this creates a potential exploitation chain:

1. Trigger pbuf payload reuse (see previous analysis)
2. Overflow pbuf payload into adjacent `altcp_pcb`
3. Overwrite vtable pointer at offset 0
4. Hijack control flow on next vtable function call

**Recommendation:** Implement vtable pointer validation, enable CFI if available, and audit all code paths that write to pbuf payloads.

---

## References

| File | Description |
|------|-------------|
| `/home/user/LwIP/src/lwip/altcp.h` | altcp_pcb definition |
| `/home/user/LwIP/src/lwip/priv/altcp_priv.h` | altcp_functions vtable |
| `/home/user/LwIP/src/core/altcp.c` | altcp_pcb allocation |
| `/home/user/LwIP/src/lwip/pbuf.h` | pbuf and pbuf_custom definitions |
| `/home/user/LwIP/src/core/pbuf.c` | pbuf allocation and management |
| `/home/user/LwIP/src/lwip/tcp.h` | tcp_pcb definitions |
| `/home/user/LwIP/src/core/tcp.c` | tcp_pcb allocation |
| `/home/user/LwIP/src/core/memp.c` | Memory pool implementation |
| `PBUF_PAYLOAD_REUSE_ANALYSIS.md` | Related pbuf payload corruption analysis |
