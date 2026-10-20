# FFXI PS2 Revival

Goal: get the PlayStation 2 version of Final Fantasy XI playable again by connecting it to a private server.

## Where things stand (October 2026)

- Square Enix shut down the PS2 and Xbox 360 versions on **March 31, 2016**. Only the PC version is still running.
- Private servers exist ([LandSandBoat](https://github.com/LandSandBoat/server)), but only for the **PC** client. PC players skip the PlayOnline login with [xiloader](https://github.com/LandSandBoat/xiloader), which a PS2 can't run.
- I couldn't find any public project that has connected a PS2 to a private server.

So there's no setup guide to follow yet. This is a reverse-engineering project, and this folder is where it starts.

## Why it can work

FFXI was **cross-platform**: PS2, PC and Xbox 360 players all shared the same game servers. That means once a PS2 gets past login, it speaks the same game protocol as a PC client of the same version. That protocol is what LandSandBoat and its predecessor DarkStar already implement.

The PS2-only part is what happens **before** the game starts: the PlayOnline login and the update check. That's the part to crack.

## The problems to solve

1. **Login.** PlayOnline on the PS2 logs in to Square Enix's servers, which no longer exist for PS2. There are two ways around that:
   - **Path A: fake the servers.** Point the PS2's DNS at your own computer and answer like PlayOnline used to. This only works if the PS2 doesn't encrypt its traffic in a way we can't fake, such as TLS with certificate checks.
   - **Path B: patch the client.** Change the game program on the HDD so it skips PlayOnline and connects straight to a lobby server. This is the PS2 version of what xiloader does on PC. A modded PS2 can run patched programs. It's more work, but it doesn't depend on breaking any encryption.
2. **Version match.** Your PS2 client is stuck at whatever version is installed on your HDD, because PS2 updates can't be downloaded anymore. Current LandSandBoat targets the 2026 PC client, and ten years of packet changes sit between the two. The likely shortcut is to run **DarkStar from the same era** as your client. Its full history is public in the [archived repo](https://github.com/DarkstarProject/darkstar). You'd also turn off the version lock: in LandSandBoat that's `VER_LOCK` / `CLIENT_VER` in `settings/default/login.lua`, and DarkStar had an equivalent.
3. **Update check.** FFXI checks for updates before it launches. Whatever replaces PlayOnline (Path A or B) also has to report that the game is up to date.

## Roadmap

### Phase 0: Inventory and dev setup
- Hardware: PS2, network adapter, and an HDD with PlayOnline and FFXI installed.
- **Find out which client version is installed.** A drive that was played until 2016 has the final PS2 version. A fresh install from disc is stuck at the disc's version. Everything on the server side depends on this.
- **Image the HDD to your PC before you change anything.** That's your backup, and it also lets you develop in [PCSX2](https://pcsx2.net/). PCSX2 emulates the HDD and network adapter and has a debugger, which makes testing much faster than restarting a real console.

### Phase 1: Recon (`tools/ps2_recon.py`, below)
Find out which hostnames and ports PlayOnline contacts, and whether its traffic is plaintext, its own protocol, or TLS.
- **Plaintext or custom protocol:** go to Path A.
- **TLS:** next, test whether the PS2 accepts a self-signed certificate. If it doesn't, go to Path B.

### Phase 2: Get past login
- **Path A:** write a fake PlayOnline server based on the captures from Phase 1.
- **Path B:** disassemble the PS2 program with [Ghidra](https://ghidra-sre.org/) and the Emotion Engine processor module ([ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded)), and step through it in PCSX2's debugger. Find where the client gets its lobby address and session key. Read xiloader's source to see what a lobby server expects from the client.

### Phase 3: Game server
Run an era-matched DarkStar build with the version lock off. Its lobby listens on TCP 54001 and 54230, and the recon tool already listens on both. Then work through character list, character creation, zoning in, and fixing whatever breaks.

### Phase 4: Share it
Publish **patches** and server config only, never Square Enix's files. That's the standard way ROM-hack projects stay distributable.

**Before you go deep:** ask in the LandSandBoat community (linked from their GitHub) whether anyone has PS2 notes. Someone may have done Phase 1 already.

## Running the recon tool

You need Python 3.8 or newer on a computer that's on the same network as the PS2. The tool uses only the standard library, so there's nothing to install.

1. Give your computer a fixed LAN IP, or check what its current IP is.
2. Start the tool:
   - Linux/macOS: `sudo python3 tools/ps2_recon.py`. Port 53 needs root.
   - Windows: open a terminal as Administrator, run `python tools\ps2_recon.py`, and allow it through the firewall when asked.

   It prints the IP it will hand out. If that's the wrong network card, pass `--ip <your LAN IP>`.
3. On the PS2, open the network configuration (PlayOnline's network settings, or any game's network setup). Set **Primary DNS** to your computer's IP and leave the other settings alone.
4. Start PlayOnline and try to log in and launch FFXI. Let it fail.
5. Press **Ctrl+C**. Everything is saved in `captures/<date-time>/`:
   - `summary.txt`: which hostnames were looked up, which ports were contacted, and what was sent. **Bring this back to continue the project.**
   - `recon.log`: the full log with hex dumps.
   - `*.bin`: the raw bytes from each connection.

### Reading the results

| You see | It means |
|---|---|
| Hostnames under "Hostnames looked up" | The servers PlayOnline expects. These are what Path A has to impersonate. |
| `TLS ClientHello` / `SSLv2-compatible ClientHello` | The traffic is encrypted. The version and cipher list show how old the SSL stack is. |
| `HTTP request` | Plaintext web traffic, which is easy to fake. It's often the update check. |
| `Unrecognised binary protocol` | Probably Square Enix's own protocol. The `.bin` files are what to study. |
| `client sent nothing` | The server is expected to speak first. Next step: capture real traffic with Wireshark. |
| DNS lookups but no connections | The PS2 is using a port this tool isn't listening on. Run [Wireshark](https://www.wireshark.org/) with the filter `host <PS2 IP>` to see which ports it tries, then add them with `--tcp` / `--udp`. |

### Options

| Option | Default | What it does |
|---|---|---|
| `--ip` | auto-detected | IP address given in DNS answers |
| `--redirect GLOB` | `*` (everything) | Redirect only matching hostnames, e.g. `'*.playonline.com'`. Everything else goes to `--upstream` and gets real answers. |
| `--forward-all` | off | Redirect nothing. Only log lookups and their real answers, e.g. to see whether old hostnames still resolve. |
| `--upstream` | `1.1.1.1` | Real DNS server used for forwarded lookups |
| `--tcp` / `--udp` | PlayOnline/FFXI ports | Ports to listen on |
| `--idle-timeout` | `5` | Seconds to wait for more data before closing a connection |

### Tests

```
python3 -m unittest discover -s tests -v
```
