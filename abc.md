# DC Core Uplink Topology (Network Change)

## Logical Topology

```mermaid
flowchart BT
    subgraph GCORE["NY G-Core"]
        GPE["G-Core PE<br/>Corporate VRF"]
    end

    subgraph MCORE["NY M-Core RR &nbsp;|&nbsp; ASN 64514"]
        RRC["M-Core RR<br/>Corporate VRF"]
        RRW["M-Core RR<br/>dc-waas VRF"]
    end

    subgraph DCPE["NY DC PE &nbsp;|&nbsp; ASN 64514"]
        PEC["DC PE<br/>Corporate VRF"]
        PEW["DC PE<br/>dc-waas VRF"]
    end

    subgraph SCMR["SCMR &nbsp;|&nbsp; ASN 64526"]
        SC["HZ SCMR<br/>Default VRF"]
    end

    subgraph HZ["HZ DC Core &nbsp;|&nbsp; ASN 64542"]
        CORE["HZ DC Core<br/>Default VRF"]
    end

    OTHER["Other DC &amp; Campus<br/>Corporate"]

    %% ---- Uplink 1: direct ----
    CORE -->|"Link 1 · direct"| PEC

    %% ---- Uplink 2: via SCMR ----
    CORE -->|"Link 2 · via SCMR"| SC
    SC --> PEW

    %% ---- DC PE -> M-Core RR (VRF-to-VRF) ----
    PEC --> RRC
    PEW --> RRW

    %% ---- Other DC / Campus ----
    OTHER --> RRC

    %% ---- M-Core RR -> G-Core PE (both VRFs into one Corporate VRF) ----
    RRC --> GPE
    RRW --> GPE

    classDef corp fill:#c8e6c9,stroke:#2e7d32,color:#1b5e20
    classDef waas fill:#66bb6a,stroke:#1b5e20,color:#ffffff
    classDef scmr fill:#bdbdbd,stroke:#616161,color:#212121
    classDef core fill:#bbdefb,stroke:#1565c0,color:#0d47a1

    class GPE,RRC,PEC,OTHER corp
    class RRW,PEW waas
    class SC scmr
    class CORE core
```

## Path Description

| # | Path | VRF Flow |
|---|------|----------|
| 1 | HZ DC Core → DC PE | Default VRF → **Corporate** VRF (direct link) |
| 2 | HZ DC Core → SCMR → DC PE | Default VRF → SCMR Default VRF → **dc-waas** VRF |
| 3 | DC PE → M-Core RR | Corporate → Corporate; dc-waas → dc-waas (two separate sessions) |
| 4 | Other DC & Campus → M-Core RR | → **Corporate** VRF |
| 5 | M-Core RR → G-Core PE | Corporate + dc-waas both merge into a **single Corporate** VRF |

## AS Numbers

| Domain | ASN |
|--------|-----|
| NY M-Core / DC PE / M-Core RR | 64514 |
| SCMR | 64526 |
| HZ DC Core | 64542 |

> Key point: the two uplinks stay VRF-isolated (Corporate / dc-waas) through DC PE
> and M-Core RR, and only converge into the same Corporate VRF at G-Core PE.
