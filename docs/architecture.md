# A Decentralized, Self-Learning Intrusion Prevention System
## Using Machine Learning and Blockchain

## 1. Project Objective

Build and experimentally evaluate a distributed intrusion prevention system
combining Suricata, machine-learning-assisted traffic analysis, controlled
rule generation, and Hyperledger Fabric-based authorization and auditing.

## 2. Symmetric Three-Node Architecture

All three nodes must be capable of performing all three roles:
1. Traffic generator / attacker simulator
2. Victim / detection and prevention
3. Observer / coordination

Roles must be configurable and rotatable between nodes. No node is permanently
restricted to one role.

### Node A — Kali Linux
Host-only interface: eth1
Host-only IP: 192.168.56.128
NAT interface: eth0

Responsibilities:
- Generate controlled traffic within the authorized lab.
- Receive test traffic and perform detection/prevention.
- Observe events and participate in coordination.
- Run its own Suricata instance.
- Run its own assigned Hyperledger Fabric node/component.

### Node B — Kali Linux
Host-only interface: eth1
Host-only IP: 192.168.56.129
NAT interface: eth0

Responsibilities:
- Generate controlled traffic within the authorized lab.
- Receive test traffic and perform detection/prevention.
- Observe events and participate in coordination.
- Run its own Suricata instance.
- Run its own assigned Hyperledger Fabric node/component.

### Node C — Ubuntu Linux
Host-only interface: ens37
Host-only IP: 192.168.56.130
NAT interface: ens33

Responsibilities:
- Generate controlled traffic within the authorized lab.
- Receive test traffic and perform detection/prevention.
- Observe events and participate in coordination.
- Run its own Suricata instance.
- Run its own assigned Hyperledger Fabric node/component.

## 3. Network Design

Host-only subnet: 192.168.56.0/24

- Windows host: 192.168.56.1
- Node A: 192.168.56.128
- Node B: 192.168.56.129
- Node C: 192.168.56.130

The host-only network is intended for inter-node experiments.
NAT interfaces are intended for controlled software installation and updates.
Verify interface names, routes, firewall policy, and traffic paths before
configuring detection or prevention.

## 4. Separate Deployments

### Suricata
Install and configure a separate Suricata instance on each VM.
Each instance must have its own configuration, rules, logs, service, and
health checks. Interface selection must be configurable to support role
rotation and controlled experiments.

### Hyperledger Fabric
Deploy a separate Fabric node/component on each VM as part of a distributed
network. Final roles, such as peer, ordering service, or client/observer,
must be designed and validated before installation. Do not assume that three
generic Fabric processes form a valid or fault-tolerant network.

Confirm compatibility, resource requirements, identities, channel configuration,
endorsement policy, certificate management, and recovery procedures first.

## 5. Persistent Processes and VS Code

- Use the shared workspace:
  Windows: D:\IPS-Lab\Shared\IPS-Project
  Linux: /mnt/hgfs/IPS-Project
- Use VS Code to edit and review project files in the shared workspace.
- Long-running services must be managed by systemd or the appropriate
  supported service manager.
- Services must have defined startup dependencies, logging, health checks,
  restart behavior, and safe shutdown procedures.
- Do not rely on manually opened terminal sessions to keep the system running.
- Keep credentials, private keys, and enrollment secrets outside shared
  source files. Never store raw secrets on the blockchain ledger.

## 6. Controlled Rule-Update Lifecycle

1. A Suricata instance detects traffic using its current rules.
2. Events are normalized and relevant features are extracted.
3. The ML component scores suspicious activity.
4. A candidate rule is generated from constrained templates or selected
   from approved rules.
5. Syntax, scope, safety, and regression checks are performed.
6. The proposed update is submitted for authorization.
7. Hyperledger Fabric records the authorized decision and audit metadata.
8. The approved artifact is delivered to the intended node.
9. The receiving node validates and tests the artifact again.
10. The local service activates the rule and records the result.
11. A known-good ruleset and tested rollback procedure remain available.

A committed blockchain transaction does not prove that an artifact was
delivered, loaded, or successfully enforced.

## 7. Safety Boundaries

- Test only on systems and traffic explicitly authorized for this lab.
- Do not target public systems or third-party networks.
- Do not automatically activate unvalidated ML-generated rules.
- Restrict rule scope and require authorization before enforcement.
- Preserve rollback capability and record all configuration changes.
- Do not expose Fabric enrollment secrets or private keys in the shared folder.

## 8. Evaluation

Measure:
- Precision, recall, F1-score, and false-positive rate.
- Detection, coordination, and rule-update latency.
- CPU, memory, and disk overhead on each node.
- Rule validation, delivery, activation, and rollback success rates.
- Authorization and audit-trail correctness.
- Behavior during node failure and recovery.
- Results when the three roles rotate between nodes.

Document dataset provenance, PCAP sources, software versions, test conditions,
limitations, and repeatable experimental procedures.

## 9. Implementation Status

This file defines the intended architecture, not completed functionality.
Verify network isolation, resource feasibility, software compatibility,
and the final Fabric topology before installing or activating components.
