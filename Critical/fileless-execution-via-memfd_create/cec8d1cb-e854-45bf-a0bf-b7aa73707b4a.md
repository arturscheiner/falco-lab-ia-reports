**Incident Report**

**Date:** 2024-10-05
**Time:** 13:00:46 UTC
**Severity:** Critical
**Host:** mini-debian-lab

**Alert Details**

* **Rule Name:** Fileless execution via memfd_create
* **Priority:** Critical
* **Source:** syscall (Falco)
* **Tags:** T1620, container, host, maturity_stable, mitre_defense_evasion, process

**Summary:**
A critical fileless execution event was detected on the mini-debian-lab host. The event occurred in a container named peaceful_mestorf, where an executable program was created using the memfd_create system call.

**Alert Content**

{
    "uuid": "cec8d1cb-e854-45bf-a0bf-b7aa73707b4a",
    "output": "14:00:46.937782756: Critical Fileless execution via memfd_create (container_start_ts=1728133229850062067 proc_cwd=/ evt_res=SUCCESS proc_sname=event-generator gparent=containerd-shim evt_type=execve user=root user_uid=0 user_loginuid=-1 process=3 proc_exepath=memfd:program parent=event-generator command=3 run helper.DoNothing terminal=34816 exe_flags=EXE_WRITABLE|EXE_FROM_MEMFD container_id=c61b4b13ae44 container_name=peaceful_mestorf)",
    "priority": "Critical",
    "rule": "Fileless execution via memfd_create",
    "time": "2024-10-05T13:00:46.937782756Z",
    "output_fields": {
        "container.id": "c61b4b13ae44",
        "container.name": "peaceful_mestorf",
        "container.start_ts": 1728133229850062067,
        "evt.arg.flags": "EXE_WRITABLE|EXE_FROM_MEMFD",
        "evt.res": "SUCCESS",
        "evt.time": 1728133246937782756,
        "evt.type": "execve",
        "proc.aname[2]": "containerd-shim",
        "proc.cmdline": "3 run helper.DoNothing",
        "proc.cwd": "/",
        "proc.exepath": "memfd:program",
        "proc.name": "3",
        "proc.pname": "event-generator",
        "proc.sname": "event-generator",
        "proc.tty": 34816,
        "user.loginuid": -1,
        "user.name": "root",
        "user.uid": 0
    },
    "source": "syscall",
    "tags": [
        "T1620",
        "container",
        "host",
        "maturity_stable",
        "mitre_defense_evasion",
        "process"
    ],
    "hostname": "mini-debian-lab"
}

**Mitigation Strategies:**

1. **Configure the container runtime to use a more secure default configuration**: By default, containerd-shim might allow executable programs to be created in memory using memfd_create. Consider configuring the container runtime to disable this feature or set a more restrictive policy.
2. **Implement additional logging and monitoring**: Configure the Falco agent to collect more detailed information about the events occurring within containers, such as process creation and execution events.
3. **Enforce stricter access controls for container creation**: Ensure that only authorized users can create new containers, and implement strict access control mechanisms to prevent unauthorized container creation.
4. **Regularly update and patch the host operating system and container runtimes**: Keeping the host and container runtimes up-to-date with security patches can help mitigate vulnerabilities that might be exploited by adversaries.
5. **Implement a more restrictive network policy for containers**: Consider implementing a network policy that restricts communication between containers, especially if they are not trusted or do not require inter-container communication.

**Command Line Options/Configuration Changes:**

1. To configure the container runtime to disable executable programs creation in memory using memfd_create, you can add the following configuration to your containerd-shim configuration file (e.g., `/etc/containerd/config.toml`):
```toml
[create_executable]
enabled = false
```
2. To implement additional logging and monitoring for process creation and execution events, modify the Falco agent's configuration file (e.g., `/etc/falco.conf`) to include the following:
```bash
log_level=INFO
output_fields=evt.type,proc.name,proc.cwd
```
3. To enforce stricter access controls for container creation, you can use a tool like `containerd-shim` with an authentication plugin (e.g., PAM) to restrict who can create new containers.

**Note:** These suggestions are meant to serve as starting points for further investigation and potential mitigation strategies. It is essential to consider the specific requirements and constraints of your environment before implementing any changes.