# Inter-component communication in Genode

An analysis of how Genode components talk to each other, traced through the
source tree (`VERSION` 26.02). All paths are relative to `repos/`.

> Note: The Genode Foundations book (genode.org) was not reachable from the
> analysis environment, so this document is derived entirely from the code.
> Terminology follows the code's names, which match the book's.

## 1. The big picture

Genode has exactly three inter-component communication primitives, layered on
top of whatever kernel it runs on:

| Mechanism                        | Direction / sync      | Carries                  | Kernel involvement               |
|----------------------------------|-----------------------|--------------------------|----------------------------------|
| **Synchronous RPC**              | client → server, blocking call + reply | small typed args, ≤4 capabilities | every call (IPC)        |
| **Asynchronous signals**         | sender → receiver, fire-and-forget    | a counter only (no payload)        | via core or kernel object |
| **Shared memory (dataspaces)**   | bidirectional, no sync of its own     | bulk data                          | only at setup (mapping)   |

Everything else — sessions, the parent protocol, ROM updates, packet streams,
block/NIC/file-system I/O — is composed from these three. All three are
**capability-based**: a component can only invoke an RPC object, signal a
context, or attach a dataspace if it holds a capability for it, and the only
ways to obtain one are to create the object yourself or to receive the
capability in an RPC message.

```
       ┌──────────── RPC (sync, small) ─────────────┐
client │                                            ▼ server
  ─────┼──── signal (async, "something happened") ──┼─────
       │                                            │
       └──── shared dataspace (bulk payload) ───────┘
```

The code is split into a kernel-independent part in `base/` and a thin
kernel-specific back end per platform in `base-<kernel>/`
(`base-hw`, `base-nova`, `base-foc`, `base-sel4`, `base-linux`,
`base-fiasco`, `base-okl4`, `base-pistachio`).

---

## 2. Capabilities: the naming layer

### 2.1 `Native_capability` and `Capability<IF>`

`base/include/base/native_capability.h` defines `Native_capability`, an
opaque, reference-counted handle to a kernel-specific `Data` object
(`_inc()`/`_dec()` on copy/destruction). Its observable properties are
`valid()`, `local_name()` and a raw 4-word representation.

`base/include/base/capability.h` wraps it in the typed
`Capability<RPC_INTERFACE>`. The type parameter is purely compile-time:

- implicit conversion is only allowed from a capability of a *derived*
  interface (`_check_compatibility` does `RPC_INTERFACE *to = from;`);
- `reinterpret_cap_cast<IF>()` / `static_cap_cast<>()` cast explicitly;
- `Capability<IF>::call<Rpc_fn>(args...)` is the actual RPC entry point (§3).

### 2.2 Internal representation

`base/src/include/base/internal/capability_data.h`: the generic
`Capability_data` holds a ref count and an **`Rpc_obj_key`** — the key by
which the server looks the target object up in its object pool. Each kernel
extends this with its own kernel-object handle (a capability selector on
NOVA/seL4/Fiasco.OC/hw, a socket descriptor on Linux, a thread ID on
Pistachio/OKL4/Fiasco). Each component keeps a
`Capability_space` (`capability_space.h`, `capability_space_tpl.h`) mapping
local names to these records; `Capability_space::import()` registers a
capability received via IPC.

### 2.3 Who mints RPC-object capabilities

Capabilities are minted by **core** on behalf of a component's PD session:
`Pd_session::alloc_rpc_cap(Native_capability ep)`
(`base/include/pd_session/pd_session.h`). The `ep` argument is the
entrypoint thread's capability; the result names a new RPC object served by
that thread. The per-kernel factory in core differs fundamentally:

| Kernel        | What `alloc_rpc_cap` creates                                                   | Source |
|---------------|-------------------------------------------------------------------------------|--------|
| base-hw       | a kernel `Kobject` (IPC object) bound to the entrypoint thread                 | `base-hw/src/core/rpc_cap_factory.h` |
| NOVA          | a **portal** (`create_pt`) bound to the EP's execution context, with the entry IP `_activation_entry` | `base-nova/src/core/rpc_cap_factory.cc` |
| Fiasco.OC     | an **IPC gate** whose label is a freshly allocated ID                           | `base-foc/src/core/rpc_cap_factory.cc` |
| seL4          | an endpoint capability minted with a unique badge                              | `base-sel4/src/core/rpc_cap_factory.cc` |
| L4 w/o caps (Pistachio, OKL4, Fiasco, Linux) | just a pair *(EP thread ID / socket, ++counter)* — no kernel object | `base/src/core/rpc_cap_factory_l4.cc` |

On the client side `Rpc_entrypoint::_alloc_rpc_cap`
(`base/src/lib/base/rpc_cap_alloc.cc`) wraps the call in a retry loop: on
`OUT_OF_RAM`/`OUT_OF_CAPS` it asks its parent to upgrade the PD session
(`_parent().upgrade(Parent::Env::pd(), "ram_quota=..., cap_quota=...")`) and
tries again. Capability allocation is thus accounted against the component's
own cap quota — a central resource-accounting property of Genode.

### 2.4 Security implication across kernels

On capability kernels (hw, NOVA, Fiasco.OC, seL4) the *kernel* delivers the
object identity (badge / gate label / portal ID) to the server, so a client
cannot forge it. On kernels without capability protection the client itself
transmits the key:

- Pistachio: `prepare_send(dst_data.rpc_obj_key.value(), ...)`
  (`base-pistachio/src/lib/base/ipc.cc:128`) puts the badge in message word 0
  and the server reads it back (`L4_Get(&msg, 0)`).
- Linux: `Protocol_header::protocol_word` is "badge of invoked object (on
  call)" (`base-linux/src/lib/base/ipc.cc:64`).

This is why `Rpc_exception_code::INVALID_OBJECT` exists: per `rpc.h`, "On
kernels with capability support, the condition can never occur. On kernels
without capability protection, the code is merely used for diagnostic
purposes."

---

## 3. Synchronous RPC

### 3.1 Declaring an interface (`base/include/base/rpc.h`)

```cpp
struct Hello : Genode::Interface {
    virtual int add(int, int) = 0;
    GENODE_RPC(Rpc_add, int, add, int, int);
    GENODE_RPC_INTERFACE(Rpc_add);
};
```

- `GENODE_RPC_THROW(name, ret, func, exc_list, args...)` expands to a struct
  carrying `Client_args` (a tuple of references), `Server_args` (a tuple of
  POD copies), `Exceptions`, `Ret_type` (`void` → `Meta::Empty`), a static
  `serve()` adapter that calls `server.func(args...)`, and `name()` for
  tracing.
- `GENODE_RPC_INTERFACE(...)` defines `Rpc_functions` as a **type list**. The
  **opcode is the index in that list** (`Meta::Index_of`).
  `GENODE_RPC_INTERFACE_INHERIT(base, ...)` appends to the base list so
  inherited opcodes keep their values.
- Argument direction is inferred from the C++ type (`Trait::Rpc_direction`):
  value / `const &` / `const *` → in; non-const `&` / `*` → in-out.
- Message sizes are computed **at compile time**:
  `Rpc_function_msg_size<IF, RPC_CALL>` = in-args + opcode;
  `<IF, RPC_REPLY>` = out-args + return value + exception code.

No IDL compiler is involved: marshalling code is produced entirely by C++
template metaprogramming.

### 3.2 Message buffer (`base/include/base/ipc_msgbuf.h`)

`Msgbuf_base` holds:

- a data area with `capacity()`, written sequentially by `insert()`, each
  item padded to machine-word alignment (`align_natural`);
- up to **`MAX_CAPS_PER_MSG = 4`** capabilities in a separate array (caps are
  never serialized as plain bytes — the kernel back end must translate them);
- a 16-word `Headroom` in front of the data that kernel back ends may use for
  a platform header (`header<T>()`), allowing zero-copy prepending.

`Rpc_in_buffer<N>` is transferred as `size` + bytes. Overflowing inserts are
silently dropped; overflowing extracts raise `IPC_BUFFER_EXCEEDED`
(`Ipc_unmarshaller` in `base/include/base/ipc.h`).

### 3.3 Client path (`base/include/base/rpc_client.h:124`, `Capability::_call`)

1. Stack-allocate `Msgbuf<CALL_MSG_SIZE + 4 words>` and
   `Msgbuf<REPLY_MSG_SIZE + 4 words>` — sized for *this* function only.
2. Insert `Rpc_opcode` = index of the function.
3. `_marshal_args`: insert every argument whose direction has `IN`.
4. Emit a `Trace::Rpc_call` event.
5. `ipc_call(dst, call_buf, reply_buf, RECEIVE_CAPS)` — the kernel-specific
   part. `RECEIVE_CAPS` (computed by `Rpc_function_caps_out`) tells kernels
   like NOVA how big a capability receive window to open.
6. Unmarshal out/in-out arguments, then translate the returned
   `Rpc_exception_code` into a C++ exception (`_check_for_exceptions`:
   code `EXCEPTION_BASE - n` ↔ n-th-from-last type of the exception list).
7. Extract and return the return value (`Attempt<R,E>` is encoded as a bool
   followed by either payload).

`Rpc_client<IF>` is merely a convenience base class holding the capability so
client stubs become `return call<Rpc_add>(a, b);`.

### 3.4 Server path

**Objects.** `Rpc_object<IF, SERVER>` (`base/include/base/rpc_server.h`)
inherits from `Rpc_object_base` (an `Object_pool` entry, keyed by the
capability's `Rpc_obj_key`) and from `Rpc_dispatcher<IF, SERVER>`, which
implements `dispatch(opcode, in, out)` as a compile-time-unrolled chain of
`if (opcode == Index_of<...>)` tests. For the matching function it:

- reads the `Server_args` tuple from the message (`_read_args`; out-only args
  are default-constructed),
- calls `SERVER::func` via `serve()` (with `SERVER` given, it calls the
  concrete class directly, avoiding a virtual call),
- writes out/in-out args, then the return value,
- converts declared C++ exceptions into an exception code
  (`throw Rpc_exception_code(...)` inside `_do_serve`),
- returns `INVALID_OPCODE` for unknown opcodes.

**Entrypoint.** `Rpc_entrypoint` is a `Thread` plus an
`Object_pool<Rpc_object_base>` with fixed 1 KiB send/receive buffers.
`manage(obj)` → `_alloc_rpc_cap` (§2.3) → `obj->cap(cap); insert(obj)`.
`dissolve(obj)` removes the object from the pool and frees the cap at core.

The generic server loop (`base/src/lib/base/rpc_dispatch_loop.cc:53`) used by
all kernels except NOVA:

```cpp
while (!_exit_handler.exit) {
    Rpc_request request = ipc_reply_wait(_caller, exc, _snd_buf, _rcv_buf);
    _caller = request.caller;
    unmarshaller.extract(opcode);
    exc = INVALID_OBJECT; _snd_buf.reset();
    apply(request.badge, [&] (Rpc_object_base *obj) {
        if (obj) exc = obj->dispatch(opcode, unmarshaller, _snd_buf); });
}
```

`ipc_reply_wait` combines the reply to the previous request with waiting for
the next one — one kernel entry per request in steady state. While the
object is being dispatched, `Object_pool::apply` holds it locked so a
concurrent `dissolve` cannot destroy it mid-call.

An entrypoint serves requests **strictly one at a time**. The deferred-reply
escape hatch (`reply_dst()`, `omit_reply()`, `reply_signal_info()`) is marked
"temporary API" and is used only by core's signal source (§4.3).

Destruction is itself done via RPC: `~Rpc_entrypoint` calls the private
`Exit` RPC object on its own entrypoint to break the loop
(`base/src/lib/base/rpc_entrypoint.cc`).

### 3.5 The kernel back ends: `ipc_call`, `ipc_reply_wait`, `ipc_reply`

These three functions (declared in `base/include/base/ipc.h` and
`base/src/include/base/internal/ipc_server.h`) are the entire kernel
interface of the RPC framework. Each `base-<kernel>/src/lib/base/ipc.cc`
implements them:

- **base-hw** (`base-hw/src/lib/base/ipc.cc:94`): copies the `Msgbuf` into
  the thread's UTCB (data + capability IDs + count), then
  `Kernel::rpc_call(capid, rcv_caps)`; server uses `rpc_reply_and_wait` /
  `rpc_wait`. The badge comes back in `utcb.destination()`. If the kernel
  reports a failure it is assumed to be lack of capability slab memory:
  `upgrade_capability_slab()` and retry. Received caps are acknowledged with
  `Kernel::cap_ack`.
- **NOVA** (`base-nova/src/lib/base/ipc.cc:31`): `Nova::call(portal)`.
  Before the call, a power-of-two-sized **receive window** of capability
  selectors is opened in the UTCB (`Receive_window::prepare_rcv_window`),
  sized from `rcv_caps`; after the call, unused delegated selectors are
  revoked/freed. The server side is radically different — NOVA has no
  "wait" syscall; instead each portal has an **entry IP**
  (`Rpc_entrypoint::_activation_entry`,
  `base-nova/src/lib/base/rpc_entrypoint.cc:128`). An incoming call
  *activates* the EP's execution context at that IP with the portal ID in
  `rdi`/`eax`; the portal ID doubles as the object-pool key. The handler
  dispatches and ends with `Nova::reply()` on the EP stack. `entry()` is
  empty. Dissolving an object revokes the portal and then sends a dummy
  "cleanup call" to the EP to make sure no activation is still inside the
  object.
- **Fiasco.OC** (`base-foc/src/lib/base/ipc.cc:256`): message words carry a
  protocol word, the cap count, and a badge per cap followed by the
  capability items for mapping; caps the receiver already owns are
  recognized by badge and translated via `cap_map().insert_map`.
- **seL4** (`base-sel4/src/lib/base/ipc.cc:318`): `seL4_Call` /
  `seL4_ReplyRecv`. Caps that the server *itself* minted arrive
  **unwrapped** (only the badge, via `capsUnwrapped`), others are delegated
  into a pre-allocated receive slot; the code reconciles both cases and
  checks `arg_badge == rpc_obj_key`.
- **Linux** (`base-linux/src/lib/base/ipc.cc:286`): RPC is emulated with
  Unix-domain sockets. Each call creates a fresh `socketpair` as a reply
  channel, `sendmsg`s the payload to the server's socket with the reply
  socket and all capability-argument sockets attached as `SCM_RIGHTS`, and
  waits on `recvmsg` of the reply socket. A `Protocol_header` carries the
  object badge and per-cap badges.
- **Pistachio / OKL4 / Fiasco** (L4 v2/X.2): `L4_Call` to the EP's thread
  ID, badge in the first message register, caps transferred as
  (thread ID, key) pairs.

### 3.6 Properties that fall out of the design

- **Synchronous, blocking, no timeouts**: a client trusts the server to reply.
  That is why Genode's design guideline is that a server must never call
  *its* clients synchronously — servers notify clients with signals instead.
- **Compile-time-sized, small messages**: one call cannot transport more than
  the function's declared args (and in practice ~1 KiB on the server side);
  bulk data must go through shared memory.
- **At most 4 capabilities per message**; the framework logs "attempt to
  transfer too many caps as IPC arguments" and drops extras.
- **Delegation is implicit**: putting a `Capability<>` in an argument or
  return value delegates it; the kernel (or Linux `SCM_RIGHTS`) transfers the
  underlying object reference.
- **Single-threaded server semantics** per entrypoint: dispatch functions run
  without internal locking concerns as long as only the EP touches the state.

---

## 4. Asynchronous signals

### 4.1 API (`base/include/base/signal.h`)

- `Signal_context` — a notification target. Managing it at a
  `Signal_receiver` yields a `Signal_context_capability`, which can be handed
  to other components via RPC.
- `Signal_transmitter(cap).submit(cnt)` — fire and forget.
- Signals carry **no payload**, only a count; multiple submissions before the
  receiver handles them are **coalesced** (`Signal_receiver::local_submit`
  adds `num`; the context becomes pending once).
- In practice components use `Signal_handler<T>` / `Io_signal_handler<T>`,
  which bind a member function to the component's `Entrypoint` (§5).

### 4.2 Generic implementation (core-mediated)

On most kernels signals are a **protocol built on RPC to core**:

1. **Context creation** (`Signal_receiver::manage`,
   `base/src/lib/base/signal.cc`): RPC `Pd_session::alloc_context(source, imprint)`
   where the **imprint is the local address of the `Signal_context`**. Core
   returns a capability for a core-side `Signal_context_component`. Quota
   exhaustion is handled by the same upgrade-and-retry loop as in §2.3.
2. **Submission** (`base/src/lib/base/signal_transmitter.cc`): the sender
   does **not** invoke the context capability; it calls
   `env.pd().submit(context_cap, cnt)` — an RPC to *its own* PD session in
   core, passing the context cap as an argument. Core resolves it to a
   `Signal_context_component`, which therefore must have been created by core.
3. **Delivery** (`base/src/core/signal_source_component.cc`): each receiving
   component has one `Signal_source` in core. `wait_for_signal()` is an RPC
   that core **does not answer** if the queue is empty: it stores
   `_entrypoint.reply_dst()` and calls `omit_reply()`. When `submit()` later
   finds a waiting client, it answers that held-back call directly with
   `reply_signal_info(reply_cap, imprint, cnt)`; otherwise it enqueues the
   context. This is the only use of out-of-order replies in the framework.
4. **Receiving thread**: every component has a dedicated
   `Signal_handler_thread` (`signal.cc`) that loops in
   `Signal_receiver::dispatch_signals(signal_source)`, calling
   `wait_for_signal()`, validating the imprint against the
   `Signal_context_registry` (a context may have been dissolved while a signal
   was in flight, and the imprint is untrusted), then `local_submit`-ting it
   to the owning `Signal_receiver`, which ups a semaphore.

So a remote signal costs: sender→core RPC + core's delayed reply to the
receiver's signal thread + a local semaphore wakeup.

### 4.3 Kernel-native accelerations

- **base-hw** (`base-hw/src/lib/base/signal_transmitter.cc`,
  `signal_receiver.cc`): signal contexts and receivers are kernel objects;
  `submit` is `Kernel::signal_submit(capid, cnt)`, reception is
  `Kernel::signal_wait` / `signal_pending` / `signal_ack`. Core is not on the
  data path.
- **NOVA** (`base-nova/src/lib/base/signal_transmitter.cc`): the context
  capability is a NOVA **semaphore**; submit is
  `sm_ctrl(cap, SEMAPHORE_UP)`, with core waking the signal source.
- **Fiasco.OC** (`base-foc/src/lib/base/signal_source_client.cc`): the
  signal source hands out an IRQ-object "semaphore"; the signal thread blocks
  with `l4_irq_receive` and then fetches the queued signal via
  `Rpc_wait_for_signal`, so it never blocks inside core.

### 4.4 Why signals exist

Signals provide the "upward" path in the trust graph: a server notifies an
untrusted client without ever blocking on it. A malicious receiver cannot
stall the sender — submissions only update a counter in core/kernel.

---

## 5. The component `Entrypoint`: merging RPC and signals

`Genode::Entrypoint` (`base/include/base/entrypoint.h`,
`base/src/lib/base/entrypoint.cc`) is what a modern component sees as
`env.ep()`. It integrates both mechanisms into one **single-threaded event
loop**:

- It owns an `Rpc_entrypoint` thread named `"ep"`. `Component::construct()`
  is itself executed *on that thread* by managing a temporary
  `Constructor_component` RPC object and calling it
  (`invoke_constructor_at_entrypoint`).
- The component's initial thread then becomes the **signal proxy**
  (`_process_incoming_signals`, line 115): it blocks on the signal receiver
  and, when something is pending, makes a local RPC
  (`_signal_proxy_cap.call<Signal_proxy::Rpc_signal>()`) to the EP. The EP
  thread then dispatches the `Signal_handler` in the same thread context that
  dispatches RPCs.

Result: all RPC dispatch functions and all signal handlers of a component run
serialized on one thread, giving a lock-free, event-driven programming model.
`wait_and_dispatch_one_io_signal()` additionally lets code on the EP block
for an I/O signal (used to wrap blocking APIs such as libc), while non-I/O
signals arriving meanwhile are queued as **deferred** and replayed later
(`_deferred_signals`).

---

## 6. Shared memory

Dataspaces (RAM, ROM, I/O memory) are referenced by `Dataspace_capability`.
A client attaches one to its address space via its region map
(`Region_map::attach`, RPC to core which then installs the mapping on page
fault or eagerly, depending on kernel). Passing the capability through an RPC
shares the memory; no kernel IPC is involved in subsequent accesses.

Two standard protocols combine shared memory with signals:

### 6.1 ROM sessions (publish/subscribe of documents)

A ROM server hands out a dataspace and a signal is sent via
`Rom_session::sigh` when new content is available; the client calls
`update()`/`dataspace()` and re-reads. This pattern is used for config,
reports and — notably — the parent protocol itself (§7).

### 6.2 Packet streams (`os/include/os/packet_stream.h`)

The bulk-I/O protocol for block, NIC, file-system, audio etc. One shared
dataspace is laid out as **submit queue | ack queue | bulk buffer**. The
queues are single-producer/single-consumer rings
(`Packet_descriptor_queue`: `volatile _head`/`_tail`, each constructed by both
sides in shared memory with only the side-owned field initialized). Packets
are `(offset, size)` descriptors into the bulk buffer, allocated by the
source.

Flow: source `alloc_packet` → fill → `submit_packet`; sink `get_packet` →
process → `acknowledge_packet`; source `get_acked_packet` →
`release_packet`. Signals are used only on the edge conditions — the header
comment enumerates them: `packet_avail` (submit queue becomes non-empty),
`ready_to_submit` (sink drained a full submit queue), `ack_avail`,
`ready_to_ack`. `Packet_descriptor_transmitter/receiver` hold
`Signal_transmitter`s for these, so in steady state with full queues there is
no kernel interaction per packet. `packet_stream_tx/` and
`packet_stream_rx/` provide the RPC interfaces for exchanging the dataspace
and signal handler capabilities at session setup.

---

## 7. Establishing communication: sessions and the parent protocol

Components cannot look each other up; a client only reaches a server by
asking its **parent** for a *session*, and the routing decision is the
parent's (ultimately init's/sandbox's configured policy). The `Parent`
interface (`base/include/parent/parent.h`) is itself an RPC interface with
functions `announce`, `session`, `session_cap`, `upgrade`, `close`,
`session_response`, `deliver_session_cap`, `session_sigh`, plus resource and
yield/heartbeat functions.

### 7.1 Client side

`Connection<SESSION>` (`base/include/base/connection.h`) builds an argument
string `label="...", ram_quota=..., cap_quota=..., <args>` and calls
`env.session<SESSION>(id, args, affinity)`. In `component.cc:117`
(`try_session`) this becomes `Parent::session(id, name, args, affinity)`. If
the server answers asynchronously, the client blocks on a local
`Signal_receiver` registered via `Parent::session_sigh`, then fetches the
capability via `Parent::session_cap(id)`. The session is identified by a
**client-local ID** (`Id_space<Parent::Client>`), never by a global name.
The destructor calls `env.close(id)`.

### 7.2 Parent side (`base/src/lib/base/child.cc:140`, `Child::session`)

1. Prefix the client's label with the child's name (labels are how policies
   identify clients; a child cannot spoof its prefix).
2. Let the policy filter args and affinity.
3. Keep part of the RAM quota for the session metadata
   (`_session_factory.session_costs()`).
4. **Transfer quota** child → parent → service provider
   (`Ram_transfer`/`Cap_transfer`, transactional with a guard that rolls
   back). The client pays for the server-side resources of its session.
5. Route via `_policy.with_route(name, label, ...)` to a `Service`
   (`base/include/base/service.h`): `Parent_service` (forward up),
   `Local_service` (parent implements it itself — e.g. core's services),
   or `Child_service`/`Async_service` (a sibling server).
6. `service.initiate_request(session)`. Synchronous services fill in
   `session.cap` immediately; otherwise the `Session_state` stays in
   `CREATE_REQUESTED` and `service.wakeup()` notifies the server.

### 7.3 Server side: session requests as a ROM

A child server learns about requests **through a ROM module named
`session_requests`** that its parent produces. `Session_state::generate_session_request`
(`base/src/lib/base/session_state.cc:57`) emits `<create id=".." service=".."
label=".."><args>…</args><affinity>…</affinity></create>`, `<upgrade>` and
`<close>` nodes; `os/include/os/session_requester.h` publishes them.

For servers written against the classic synchronous `Root` interface,
`base/src/lib/base/root_proxy.cc` bridges the gap: `Parent::announce(name,
root_cap)` registers the root locally and announces the name to the parent,
and a `Signal_handler` on the `session_requests` ROM
(`_handle_session_requests`, line 238) processes `upgrade`, then `close`,
then `create` requests, calling `Root::session/upgrade/close` and reporting
back with `Parent::deliver_session_cap(id, cap)` or
`Parent::session_response(id, DENIED|OK|CLOSED|...)`. The parent then flips
the client's `Session_state` to `AVAILABLE` and fires the client's
`session_sigh`.

This design means **no parent ever blocks on a child**: the parent→server
direction uses a ROM + signal, the server→parent direction uses RPC.

### 7.4 After setup

Once the client holds the session capability, it talks to the server
**directly** with RPC (kernel IPC from client thread to server EP); the
parent is no longer on the data path. Typical sessions then exchange signal
handler and dataspace capabilities over that RPC channel to set up the
asynchronous and shared-memory paths of §4 and §6.

---

## 8. End-to-end example: a block read

1. Client `Block::Connection` → `Parent::session("Block", "label=..,ram_quota=..")`.
2. Init routes by label to the block driver, transfers quota, writes
   `<create>` into the driver's `session_requests` ROM, signals it.
3. Driver's root proxy creates a session object (`Rpc_object`), `manage()`s it
   (core mints a cap), and `deliver_session_cap`s it.
4. Client gets the cap; its `Packet_stream_source` attaches the tx dataspace
   obtained via RPC and registers signal handlers.
5. Per request: client writes a descriptor into the shared submit queue and
   submits `packet_avail` only if the queue was empty; driver processes it,
   puts it in the ack queue, signals `ack_avail` if needed.
6. No synchronous RPC on the data path; the driver never blocks on the client.

---

## 9. Key files

| Topic | File |
|---|---|
| RPC declaration macros, opcodes, sizes | `base/include/base/rpc.h` |
| Client stub logic | `base/include/base/rpc_client.h` |
| Dispatcher, `Rpc_object`, `Rpc_entrypoint` | `base/include/base/rpc_server.h` |
| Message buffer | `base/include/base/ipc_msgbuf.h`, `base/include/base/ipc.h` |
| Generic server loop | `base/src/lib/base/rpc_dispatch_loop.cc` |
| Kernel IPC back ends | `base-*/src/lib/base/ipc.cc` |
| NOVA portal activation | `base-nova/src/lib/base/rpc_entrypoint.cc` |
| Capabilities | `base/include/base/{native_capability,capability}.h`, `base/src/include/base/internal/capability_*.h` |
| Core cap factory | `base*/src/core/rpc_cap_factory*.{h,cc}` |
| Signals (generic) | `base/include/base/signal.h`, `base/src/lib/base/signal*.cc`, `base/src/core/signal_source_component.cc` |
| Signals (hw/nova/foc) | `base-hw/src/lib/base/signal_*.cc`, `base-nova/src/lib/base/signal_transmitter.cc`, `base-foc/src/lib/base/signal_source_client.cc` |
| Component entrypoint | `base/src/lib/base/entrypoint.cc` |
| Parent / sessions | `base/include/parent/parent.h`, `base/include/base/connection.h`, `base/src/lib/base/{component,child,session_state,root_proxy}.cc`, `base/include/base/service.h` |
| Packet stream | `os/include/os/packet_stream.h`, `os/include/packet_stream_{tx,rx}/` |
