# Live servers (INTEGRATE)

Started from the INTEGRATE worktree (Git Bash), one combined `judged-serve` job serving qwen3.8:27b and Kev-4B on one GPU.

- Command: `model/deploy/judged-up.sh` -> Slurm job id `338762`, node `avenue` (cluster crimson, via origami)
- Model tunnel: `model/deploy/connect.sh 338762` (background); listening ssh.exe Windows PID 59292
- Kev tunnel: `model/deploy/kev-connect.sh 338762` (background); listening ssh.exe Windows PID 16396
- `model/.env` was copied from `C:\JR Cache\se201-lgtm\model\.env` into the worktree (gitignored)

## URLs and probes
- Model: http://127.0.0.1:11435 (`curl http://127.0.0.1:11435/api/tags` lists qwen3.8:27b)
- Judge: http://127.0.0.1:8008 (`curl http://127.0.0.1:8008/v1/models` lists kev-latest, jaredpalmer/kev-4b@v1.0); request path /v1/systemone

## CLI flags for the journeys
- `--gpu-cluster` (or `--gpu-model qwen3.8-27b`) for the model
- `--judge-endpoint http://127.0.0.1:8008`

## Shutdown (Git Bash, from the INTEGRATE worktree root)
1. Close tunnels: `taskkill //PID 59292 //F` and `taskkill //PID 16396 //F`
   (also `ps | grep connect.sh` to find the wrapper shells and `kill` them)
2. Cancel the job: `model/deploy/down.sh 338762`
3. Delete the copied settings: `rm model/.env`

## Outage 2026-10-26 12:04
- Reported: servers stopped answering around 11:49 local.
- Probes at 2026-10-26 12:04 : 127.0.0.1:11435/api/tags -> 000 (no connection); 127.0.0.1:8008/v1/models -> 000 (no connection).
- Tunnel ssh.exe PIDs 59292 and 16396: neither exists.
- Cluster query for Slurm job 338762 (squeue/sacct and logs/*-338762.out via model/deploy/lib.sh remote): failed, ssh to the origami login node 10.193.104.102:22 timed out. Job state, end time, exit reason and log lines not obtained.
- Journey-2 processes stopped (evaluate_real.py PIDs 24608, 40684); tmp/journey-2 and final/checks-journey-2.md removed.

## Attempt 3 start
- 2026-10-26 12:56 local: failed, cluster unreachable. ssh to the origami login node 10.193.104.102:22 timed out (via model/deploy/lib.sh remote).
- Job 338762: state not obtained; not cancelled.
- No job submitted, no tunnels started, no servers running. The copied model/.env was removed from the worktree.

## Attempt 4 start
- 2026-10-26 12:59 local: failed, cluster unreachable. ssh hostname via model/deploy/lib.sh remote (ConnectTimeout 20) to 10.193.104.102:22: Connection timed out.
- Find-NetRoute -RemoteIPAddress 10.193.104.102: InterfaceAlias WiFi, source 192.168.200.125, next hop 192.168.200.1, prefix 0.0.0.0/0.
- Test-NetConnection 10.193.104.102 -Port 22: InterfaceAlias WiFi, SourceAddress 192.168.200.125, TcpTestSucceeded False (ping timed out).
- Job 338762: state not obtained; not cancelled.
- No job submitted, no tunnels started. The copied model/.env was removed from the worktree.

## Attempt 5 start
- 2026-10-26 13:47 local: failed, cluster unreachable. `remote "hostname; squeue ...; sacct ..."` via model/deploy/lib.sh to 10.193.104.102:22: `ssh: connect to host 10.193.104.102 port 22: Connection timed out`.
- Job 338762: state not obtained; not cancelled.
- No job submitted, no tunnels started. The copied model/.env was removed from the worktree.

## Attempt 5 retry
- 2026-10-26 13:56 local: failed, cluster unreachable. `remote "hostname; squeue -h -j 338762 ...; sacct ..."` via model/deploy/lib.sh to 10.193.104.102:22: `ssh: connect to host 10.193.104.102 port 22: Connection timed out`.
- Job 338762: state not obtained; not cancelled.
- No job submitted, no tunnels started. The copied model/.env was removed from the worktree.

## Attempt 6: connection diagnosis (2026-10-26 ~14:50 local)

- GlobalProtect reports Connected: portal and gateway SMUResearch, IPSec, last authenticated 09:48:42 local, then a status refresh every hour (10:48, 11:48, 12:48, ...). The PANGP adapter "Ethernet 3" is Up with address 172.16.30.25/32 and is in the Connected state.
- Route: the active route 10.193.104.0/24 is on-link via 172.16.30.25 with metric 1. It is the only 10.x route. The default route goes via Wi-Fi (192.168.200.1).
- Despite that route, Find-NetRoute and Test-NetConnection pick Wi-Fi (source 192.168.200.125) for 10.193.104.102. tracert leaves through 192.168.200.1, then 192.168.100.254, then 154.196.231.254.
- Data plane: four pings to 10.193.104.102 left the PANGP BytesIn and BytesOut counters unchanged (18351912 and 31926587). No traffic enters the tunnel.
- TCP 22: timeout on 10.193.104.102 and on 10.193.104.1, .101 and .103. Ping: 100% loss.
- DNS: origami.smu.edu.sg did not resolve. The PANGP DNS servers are 192.168.10.249 and 192.168.100.254. Not needed, because lib.sh connects to the IP directly.
- Alternate hosts: the repo names only 10.193.104.102 (= origami.smu.edu.sg); there is no alternate login node.
- Failing layer: the GlobalProtect data plane on this machine. The client and routing table report the tunnel up, but packets for 10.193.104.0/24 never enter the adapter. The outage began at about 11:49, around the 11:48:42 hourly refresh. The VPN needs a reconnect, which this build may not do (no VPN, network, or system changes).
- Job 338762: still not queryable; state unknown, not cancelled.
