# Microsoft Threat Modeling Tool - SDN-NIDPS Design Guide

## Installation

1. Download MTMT from: https://aka.ms/threatmodelingtool
2. Install on Windows machine
3. Launch the tool

## Creating Your SDN-NIDPS Threat Model

### Step 1: Create New Model

1. File → New
2. Save as: `SDN-NIDPS-ThreatModel.tm7`

### Step 2: Define System Components

#### 2.1 Data Flow Diagram (DFD) Elements

**Add the following elements to your diagram:**

1. **External Entities** (rectangles):
   - Network Administrator
   - Legitimate User
   - Attacker (External)
   - Attacker (Internal)

2. **Processes** (circles):
   - Ryu SDN Controller
   - Suricata IDS Engine
   - Threat Detection Module
   - Flow Rule Installer
   - Web Dashboard
   - REST API Server

3. **Data Stores** (parallel lines):
   - Threat Log Database
   - Flow Rules Repository
   - Suricata Alert Log
   - Configuration Database
   - Audit Trail Storage

4. **Data Flows** (arrows connecting components):
   - Network Traffic → Suricata IDS
   - Suricata IDS → Threat Detection Module
   - Threat Detection Module → SDN Controller
   - SDN Controller → OpenFlow Switches
   - REST API → Web Dashboard
   - All components → Threat Log Database

5. **Trust Boundaries** (dotted boxes):
   - Control Plane (Ryu Controller, APIs)
   - Data Plane (Mininet Network)
   - Management Plane (Dashboard)
   - External Network

### Step 3: Configure Element Properties

#### For Ryu SDN Controller Process:
- **Process Name**: Ryu SDN Controller
- **Category**: Backend Process
- **Authentication**: TLS Certificate
- **Authorization**: Role-Based Access Control
- **Input Validation**: OpenFlow Protocol Validation
- **Encryption**: TLS 1.3
- **Logging**: Comprehensive audit logging

#### For Suricata IDS Engine:
- **Process Name**: Suricata IDS Engine
- **Category**: Detection System
- **Data Sources**: Network Packets
- **Rules Source**: Custom + ET Rules
- **Alert Output**: EVE JSON format
- **Performance**: Real-time processing

#### For Web Dashboard:
- **Process Name**: Web Dashboard
- **Category**: User Interface
- **Authentication**: Session-based
- **Authorization**: Admin roles
- **Input Validation**: XSS prevention, CSRF tokens
- **Encryption**: HTTPS required

#### For Threat Log Database:
- **Data Store**: SQLite/PostgreSQL
- **Encryption**: At-rest encryption
- **Backup**: Automated backups
- **Retention**: 90 days
- **Access Control**: Limited to controller only

### Step 4: Define Threats Using STRIDE

**MTMT will auto-generate threats based on your DFD. Review and customize:**

#### Example Threats Generated:

**1. Spoofing: Attacker Impersonates Controller**
- **Category**: Spoofing
- **Risk**: High
- **Description**: Attacker could impersonate SDN controller to inject malicious flow rules
- **Mitigation**: 
  - Implement mutual TLS authentication
  - Certificate pinning on switches
  - Controller identity verification
- **Status**: Mitigated

**2. Tampering: Flow Rule Modification**
- **Category**: Tampering
- **Risk**: High
- **Description**: Attacker modifies flow rules to redirect traffic
- **Mitigation**:
  - Flow rule integrity checking
  - Cryptographic signing of rules
  - Audit logging of all changes
- **Status**: Mitigated

**3. Repudiation: Attack Actions Not Logged**
- **Category**: Repudiation
- **Risk**: Medium
- **Description**: Attacker covers tracks by deleting logs
- **Mitigation**:
  - Write-once log storage
  - Centralized logging server
  - Log integrity verification
- **Status**: Mitigated

**4. Information Disclosure: Network Topology Exposure**
- **Category**: Information Disclosure
- **Risk**: Medium
- **Description**: Attacker gains knowledge of network structure
- **Mitigation**:
  - API authentication and authorization
  - Rate limiting on information queries
  - Minimal information disclosure principle
- **Status**: Mitigated

**5. Denial of Service: Controller Flooding**
- **Category**: Denial of Service
- **Risk**: Critical
- **Description**: Attacker floods controller with packet-in messages
- **Mitigation**:
  - Rate limiting on packet-in processing
  - Connection throttling
  - Resource monitoring and alerting
- **Status**: Mitigated

**6. Elevation of Privilege: Unauthorized Controller Access**
- **Category**: Elevation of Privilege
- **Risk**: Critical
- **Description**: Attacker gains administrative access to controller
- **Mitigation**:
  - Strong authentication (2FA)
  - Principle of least privilege
  - Regular security audits
  - API key rotation
- **Status**: Mitigated

### Step 5: Document Mitigations

For each threat, document:

1. **Current State**: Is it mitigated, partially mitigated, or not addressed?
2. **Mitigation Strategy**: Technical controls implemented
3. **Residual Risk**: Remaining risk after mitigation
4. **Testing Method**: How to verify the mitigation works

### Step 6: Generate Reports

1. Click "Reports" → "Create Full Report"
2. Export as:
   - HTML (for presentation)
   - Word (for documentation)
   - Excel (for tracking)

### Step 7: Threat Model Properties

Configure these in Model Properties:

- **Model Name**: SDN-NIDPS v1.0
- **Owner**: [Your Name]
- **Reviewer**: [Faculty Name]
- **Review Status**: Approved
- **Version**: 1.0
- **Last Updated**: [Current Date]

## MTMT Best Practices for Your Project

### 1. Detailed DFD
- Include all components from your architecture
- Show data flows between components
- Mark trust boundaries clearly

### 2. Complete Threat Coverage
- Address all auto-generated threats
- Add custom threats specific to SDN
- Document why certain threats don't apply

### 3. Practical Mitigations
- Map mitigations to actual code implementation
- Reference specific files and functions
- Include verification steps

### 4. Regular Updates
- Update model when architecture changes
- Re-run threat analysis after modifications
- Track mitigation implementation status

## Demonstration Tips

1. **Show the DFD**: Walk through your system architecture
2. **Explain Trust Boundaries**: Why components are in different zones
3. **Review Key Threats**: Focus on 3-5 most critical threats
4. **Demonstrate Mitigations**: Show how your code addresses threats
5. **Present Reports**: Use generated HTML report for professional presentation

## Integration with Your Project

Your threat model maps to these implementations:

| MTMT Component | Implementation File |
|----------------|---------------------|
| SDN Controller | `sdn_controller.py` |
| Threat Detector | `ThreatDetector` class |
| IDS Integration | `suricata_manager.py` |
| Flow Enforcement | `add_flow()`, `block_host()` |
| Logging | Threat log database |
| Dashboard | `advanced_dashboard.html` |

## Deliverables

1. `.tm7` file (threat model)
2. HTML report (for presentation)
3. Word document (detailed documentation)
4. Threat tracking spreadsheet
5. Architecture diagram
