---
Build closed: INTEGRATE - blocked (environment: GlobalProtect data plane)

Branch: build/issue-21-lgtm-flow/INTEGRATE
Head: b22978ec716419791343945e73d5a6f0f2c06834 (unsquashed)

Diagnosis: GlobalProtect reports Connected (gateway SMUResearch, IPSec), and the active route for 10.193.104.0/24 points at the VPN adapter. But packets to the cluster login node 10.193.104.102 never enter the adapter: its byte counters stay flat during pings, and the OS sends the traffic out over Wi-Fi. TCP 22 times out on every host in the subnet that was tried. The outage started at about the 11:48 hourly VPN refresh. The repo has no alternate login node. The VPN needs a reconnect, and this build does not change VPN or network settings.

Status: journey 1 passed earlier. Journeys 2-4, the live servers, and the squash are still outstanding. Nothing is running locally.

Outstanding: cluster job 338762 from an earlier attempt is still in an unknown state and has not been cancelled.

needs_replan: unchanged from the previous closed note.

Summary: reconnect GlobalProtect, confirm `ssh <user>@10.193.104.102 hostname` works, and resume INTEGRATE from b22978e.
---
