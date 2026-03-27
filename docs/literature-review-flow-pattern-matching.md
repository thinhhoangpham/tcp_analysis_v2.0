# Literature Review: Pattern Matching on Flow Arc Data for Attack Characterization

Compiled 2026-03-26. Five parallel research threads, deduplicated and organized.

---

## 1. TCP Connection Outcome as Attack Fingerprint

Papers using flow close types (RST, FIN, timeout, incomplete handshake) as the primary signal for identifying attacks.

### BOTection (AlAhmadi et al., 2020) -- ACM AsiaCCS
- Builds **Markov chains over Zeek `conn_state`** values (S0/SF/REJ/RSTO/RSTR) to fingerprint botnet families
- 99.78% F-measure; generalizes to unseen families at 93%
- **Most directly relevant paper** -- `conn_state` is essentially identical to the project's close_type
- https://dl.acm.org/doi/10.1145/3320269.3372202
- PDF: https://seclab.bu.edu/people/gianluca/papers/botection-asiaccs2020.pdf

### SYN Flood via Handshake Anomalies (Bellaiche & Gregoire, 2012) -- Wiley Sec. Comm. Networks
- Taxonomy of handshake outcomes: graceful, RST-abort, incomplete, immediate reset
- CUSUM on ratios over time for real-time SYN flood detection
- https://onlinelibrary.wiley.com/doi/full/10.1002/sec.365

### Slow Port Scan Detection (Ring et al., 2018) -- PLOS ONE
- RST count and failed-connection ratios as primary features
- Distinguishes SYN/FIN/Xmas/null scans by close-type distribution
- https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0204507

### HMM for SSH Brute-Force (Sperotto et al., 2009) -- DSOM/Springer
- 3-phase attack (scan -> brute-force -> die-off) as HMM over flow outcomes
- https://link.springer.com/chapter/10.1007/978-3-642-04989-7_13

### TCP Flow Data for Scan Detection (Sperotto et al., 2008) -- IEEE IPOM
- Classifies attack types by which flows complete gracefully, abort with RST, or go unanswered
- https://ieeexplore.ieee.org/document/4772645/

### Overview of IP Flow-Based IDS (Sperotto et al., 2010) -- IEEE Comm. Surveys
- Foundational survey establishing flow termination reason as primary feature class
- https://dl.acm.org/doi/10.1109/SURV.2010.032210.00054

### Flow-based IDS: Techniques & Challenges (Umer et al., 2017) -- Computers & Security
- Taxonomy of flow-based IDS; identifies temporal behavior across flows as significant gap
- https://www.sciencedirect.com/article/abs/pii/S0167404817301165

### The Early Bird Gets the Botnet (Abaid et al., 2016) -- IEEE LCN
- Markov chain predicting whether scanning escalates to attack from connection outcome sequences; >98% accuracy
- https://ieeexplore.ieee.org/document/7796763/

### Robustness of Markov-Chain Model (Ye et al., 2004) -- IEEE Trans. Reliability
- Theoretical grounding for Markov-chain anomaly detection from connection state transitions
- https://ieeexplore.ieee.org/document/1282169/

### TCP Classification Using Markov Models (Munz et al., 2010) -- TMA/Springer
- First few packets' sequence sufficient for classification; same technique applicable to attack traffic
- https://link.springer.com/chapter/10.1007/978-3-642-12365-8_10

### Markov Chain Fingerprinting for Encrypted Traffic (Korczynski & Duda, 2014) -- IEEE INFOCOM
- Transition probabilities uniquely fingerprint communication patterns
- https://ieeexplore.ieee.org/document/6848005/

### SYN Flood/Portscan Sampling (Korczynski et al., 2011) -- IEEE ICC
- Flood = many SYN with no ACK completion; scan = many SYN with RST responses
- https://ieeexplore.ieee.org/document/5962593

### Mining Anomalies via Feature Distributions (Lakhina et al., 2005) -- ACM SIGCOMM
- Entropy of flow features (including termination patterns) distinguishes attack categories
- https://dl.acm.org/doi/10.1145/1090191.1080118

### Labeled Dataset for Flow-Based IDS (Sperotto et al., 2009) -- IPOM/Springer
- Honeypot-based labeled flow dataset with ground-truth attack phases and TCP flag aggregates
- https://link.springer.com/chapter/10.1007/978-3-642-04968-2_4

### Real-Time IDS for NetFlow/IPFIX (Hofstede et al., 2013) -- CNSM
- Flow close type (FIN/RST vs timeout) is both detection signal and response latency gating factor
- https://ieeexplore.ieee.org/document/6727841/

---

## 2. Temporal Pattern Matching & Sequential Mining

Theory and practice of matching ordered event sequences in network traffic.

### Frequent Episodes in Event Sequences (Mannila et al., 1997) -- Data Mining & KD
- Foundational WINEPI/MINEPI algorithms for mining recurring event sequences in time windows
- https://link.springer.com/article/10.1023/A:1009748302351

### Data Mining for Intrusion Detection (Lee & Stolfo, 1998) -- USENIX Security
- First to formalize that ordered sequences of connection events define attack signatures
- https://www.usenix.org/conference/7th-usenix-security-symposium/data-mining-approaches-intrusion-detection

### Interval Temporal Logic Matching (Tzermias et al., ~2007) -- Springer LNCS
- Finding precise temporal location of multi-event attack signatures (first/all/shortest match)
- https://link.springer.com/chapter/10.1007/978-3-540-73986-9_24

### Temporal Logic IDS (Naldurg et al., 2004) -- FORTE/Springer
- Intrusion patterns as temporal logic formulas; supports sequences and statistical regularities
- https://link.springer.com/chapter/10.1007/978-3-540-30232-2_23

### Attack Episode Mining -> FSM (Su, 2010) -- J. Network & Computer Applications
- Mines frequent episode rules from honeypot logs, instantiates as FSMs for real-time detection
- https://www.sciencedirect.com/article/abs/pii/S1084804509001337

### Closed Multi-Dimensional Sequential Pattern Mining (Brahmi & Ben Yahia, 2013) -- DEXA/Springer
- Multi-stage attack chains from IDS alerts without exhaustive scanning
- https://link.springer.com/chapter/10.1007/978-3-642-40173-2_38

### Sequential Rule Mining on Security Alerts (Husak et al., 2017) -- ACM ARES
- Sequential mining on 16M real security alerts; predictive of subsequent attacks
- https://dl.acm.org/doi/pdf/10.1145/3098954.3098981

### Efficient Sequential Intrusion Pattern Mining (Shyu et al., 2009) -- Springer
- Inter-transactional temporal association rules capturing ordering across flows
- https://link.springer.com/chapter/10.1007/978-0-387-88735-7_6

### Real-time Flow Analysis (Munz & Carle, 2007) -- IEEE IM
- TOPAS framework for real-time NetFlow analysis; 48K flows/sec with concurrent detection modules
- https://www.net.in.tum.de/fileadmin/TUM/members/muenz/documents/muenz07real-time-analysis.pdf

### MalPhase (Piskozub et al., 2021) -- ACM AsiaCCS
- Sliding-window over flow sequences + autoencoder for fine-grained malware classification
- https://dl.acm.org/doi/10.1145/3433210.3453101

### FlowChronicle (Cuppers et al., 2024) -- ACM CoNEXT
- Proves flows have meaningful temporal dependency patterns; learnable and human-readable
- https://dl.acm.org/doi/10.1145/3696407

### Sequential Pattern Mining for IDS (Oikonomou et al., 2024) -- ACM ICFNDS
- Unsupervised SPM discovers attack signatures; >99% TPR, 0% FPR
- https://dl.acm.org/doi/fullHtml/10.1145/3644713.3644803

### Temporal NIDS Taxonomy (Parlanti & Catania, 2025) -- arXiv
- Names "Inter-Flow Sequential" as broadest coverage but least explored category
- **Positions our approach in an identified research gap**
- https://arxiv.org/abs/2511.03799

### Attack-Intent Sequence Learning (Yue et al., 2024) -- Computers & Security
- Attack-intent-labeled flow sequences matched by semantic model for APT detection
- https://www.sciencedirect.com/article/abs/pii/S016740482400049X

### Temporal Cyber Attack Detection (Tavallali et al., 2017) -- Sandia/DOE
- Probabilistic FSA for temporal attack graphs with inter-step dependencies
- https://www.osti.gov/biblio/1409921

---

## 3. Attack Description Languages & DSLs

Design precedents for the pattern language.

### STATL (Eckmann, Vigna, Kemmerer, 2002) -- J. Computer Security
- Canonical state/transition attack description language; domain-extensible
- https://sites.cs.ucsb.edu/~vigna/publications/2002_eckmann_vigna_kemmerer_jcs02.pdf

### NetSTAT (Vigna & Kemmerer, 1998) -- ACSAC
- Network-level FSM with hypergraph topology model; first multi-flow pattern language
- https://sites.cs.ucsb.edu/~vigna/publications/1998_vigna_kemmerer_acsac98.pdf

### Bro/Zeek (Paxson, 1998) -- USENIX Security
- Event-driven scripting DSL for multi-flow behavioral patterns; persistent cross-connection state
- https://www.icir.org/vern/papers/bro-CN99.pdf

### LAMBDA (Cuppens & Ortalo, 2000) -- RAID/Springer
- Logic-based pre/post-condition attack descriptions; compositional sequencing
- https://link.springer.com/chapter/10.1007/3-540-39945-3_13

### ADeLe (Michel & Me, 2001) -- IFIP/SEC
- EXPLOIT + DETECTION + RESPONSE structure; human-readable attack specifications
- https://link.springer.com/chapter/10.1007/0-306-46998-7_25

### Hyper-Alert Correlation (Ning et al., 2002) -- ACM CCS
- Prerequisite-consequence chaining algebra for assembling attack scenarios from alerts
- https://dl.acm.org/doi/10.1145/586110.586144

### CAML (Cheung et al., 2003) -- DISCEX III
- Modular predicate-library pattern language; reusable pattern presets
- https://www.csl.sri.com/papers/cheung-lindqvist-fong-discex3-cr/cheung-lindqvist-fong-discex3-cr.pdf

### Network Attack Query Language (Chen et al., 2006) -- IEEE ICDE
- SQL + temporal/spatial aggregates over flow data
- https://ieeexplore.ieee.org/document/1623823/

### Multi-Step Pattern on Normalized Logs (Jaeger & Ussath, 2015) -- IEEE CSCloud
- Normalized event schema before matching; integration with threat intelligence
- https://ieeexplore.ieee.org/document/7371512

### STIX Complex Patterns (Ussath et al., 2016) -- ITNG/Springer
- Temporal inter-object relations extending STIX for multi-event patterns
- https://link.springer.com/chapter/10.1007/978-3-319-32467-8_20

### Kill Chain State Machines (Wilkens et al., 2021) -- ACM CCS Workshop
- FSM over kill chain stages; 446K alerts -> 700 scenario graphs
- https://arxiv.org/abs/2103.14628

### Auto CEP Rules for IoT Attacks (2023) -- Elsevier EAAI
- Auto-generated CEP rules with `->`, `within()`, `NOT` -- same operators as project DSL
- https://www.sciencedirect.com/science/article/pii/S0952197623005286

### Multi-Step Attack Detection Survey (Shaukat et al., 2018) -- Computers & Security
- 181 publications, 119 methods surveyed and taxonomized
- https://www.sciencedirect.com/science/article/abs/pii/S0167404818302141
- Full PDF: https://publis.icube.unistra.fr/docs/13114/survey%20multistep%20attacks.pdf

### ChronoCTI (Rossi et al., 2024/25) -- Knowledge & Information Systems
- LLM pipeline extracting temporal attack patterns from 713 CTI reports; 124 patterns in 9 categories
- https://arxiv.org/abs/2401.01883

### MITRE Attack Flow v3 (2022-23) -- MITRE CTID
- Industry-standard STIX-based language for multi-step attack sequences
- https://center-for-threat-informed-defense.github.io/attack-flow/language/

### Sigma Correlation Rules (2017+) -- Open standard
- YAML ordered temporal proximity chains; deployed in production SIEMs
- https://sigmahq.io/docs/meta/correlations.html

---

## 4. Multi-Stage Attack / Kill Chain Detection

### Cyber Kill Chain (Hutchins et al., 2011) -- Lockheed Martin
- Foundational: Recon -> Weaponize -> Deliver -> Exploit -> Install -> C2 -> Exfiltrate
- https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf

### Alert Correlation (Ning et al., 2002) -- ACM CCS
- Prerequisite-consequence chaining builds attack scenario graphs
- https://dl.acm.org/doi/10.1145/586110.586144

### Comprehensive Alert Correlation (Valeur et al., 2004) -- IEEE TDSC
- Canonical pipeline: normalization -> aggregation -> correlation -> scenario construction
- https://sites.cs.ucsb.edu/~vigna/publications/2004_valeur_vigna_kruegel_kemmerer_TDSC_Correlation.pdf

### Attack Scenario via Intrusion Semantics (Barzegar & Shajari, 2018) -- Expert Sys. w/ Applications
- Ontology-based semantic similarity for automatic causal alert linking
- https://www.sciencedirect.com/science/article/abs/pii/S0957417418302689

### AGCM (Lyu et al., 2024) -- Computer Communications
- Graph aggregation clusters flows into attack stages without prior templates
- https://www.sciencedirect.com/science/article/abs/pii/S0140366424002263

### MIF (Li et al., 2021) -- Computer Networks
- Multi-info fusion: time + risk across flow events into weighted causal graph
- https://www.sciencedirect.com/science/article/pii/S1389128621003376

### MAAC (Wang et al., 2021) -- IEEE TrustCom
- Four-stage taxonomy (scan/exploit/access/post-attack); reduces alert volume 90%
- https://arxiv.org/abs/2011.07793

### Anomaly-Based Multi-Stage (Chen et al., 2024) -- PLOS ONE
- HMM over sequential alert states; >99% accuracy on DARPA/CICIDS
- https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0300821

### GRAIN (Chen et al., 2024) -- Computers & Security
- RL + GNN for causality discovery in multi-step attack reconstruction
- https://www.sciencedirect.com/science/article/abs/pii/S0167404824004851

### CONTINUUM (Mansour Bahar et al., 2025) -- arXiv
- Spatio-temporal GNN Autoencoder for APT detection across time windows
- https://arxiv.org/abs/2501.02981

### Multi-Stage GNN for IoT (Nassif et al., 2024) -- arXiv
- 3-stage GCN pipeline inspired by kill chain; ~94% F1
- https://arxiv.org/abs/2404.18328

### APTHunter (Mahmoud & Mannan, 2022) -- ACM DTRAP
- Provenance queries on system graph for early-stage APT detection
- https://dl.acm.org/doi/10.1145/3559768

### APT Framework via BiLSTM+DGCNN (Nguyen et al., 2023) -- J. Intell. Fuzzy Systems
- BiLSTM-Attention for APT IP behavioral profiles from flow sequences
- https://journals.sagepub.com/doi/abs/10.3233/JIFS-221055

### Temporal Analysis of NetFlow Datasets (Meftah et al., 2025) -- arXiv
- Identifies missing temporal features in standard NetFlow IDS benchmarks
- https://arxiv.org/abs/2503.04404

### Learning APT Chains from CTI (Husari et al., 2019) -- ACM HotSoS
- NLP extraction of TTP chains from CTI reports; maps to MITRE ATT&CK
- https://dl.acm.org/doi/10.1145/3314058.3317728

---

## 5. Visualization Systems for Network Attack Analysis

### TimeArcs (Dang, Forbes, Cao, 2016) -- EuroVis/CGF
- Foundational paper for the project's arc-based temporal network visualization
- https://onlinelibrary.wiley.com/doi/abs/10.1111/cgf.12882
- GitHub: https://github.com/CreativeCodingLab/TimeArcs

### Isis (Stanford, 2007) -- VizSEC Best Paper
- IP-row timelines + SQL queries for flow investigation; same layout paradigm
- https://link.springer.com/chapter/10.1007/978-3-540-78243-8_6

### VisFlowConnect (Yin et al., 2004) -- ACM VizSEC
- Parallel-axes link-based flow visualization for security
- https://dl.acm.org/doi/10.1145/1029208.1029214

### TNV (Goodall et al., 2005) -- VizSEC/IEEE
- Host x time matrix with connection arcs; "big picture" + detail-on-demand
- https://www.researchgate.net/publication/4187784_Preserving_the_big_picture_visual_network_traffic_analysis_with_TNV

### NFlowVis (Fischer et al., 2008) -- IEEE VizSEC
- IDS alerts overlaid on flow arcs; parallels Ground Truth + arc approach
- https://bib.dbvis.de/uploadedFiles/7.pdf

### OCEANS (Chen et al., 2014) -- VizSEC
- Multi-level temporal IP views built with D3.js; same tech stack
- https://www.researchgate.net/publication/287643401_OCEANS_online_collaborative_explorative_analysis_on_network_security

### Query-Driven Visualization (Bethel et al., 2006) -- IEEE VAST
- Interactive query language over 2.5B NetFlow records + visualization
- https://ieeexplore.ieee.org/iel5/4035729/4035730/04035755.pdf

### AlertWheel (Dumas et al., 2012) -- IEEE Network
- Radial bipartite arc diagram for IDS alerts; validates arc layout for security
- https://ieeexplore.ieee.org/document/6375888/

### MVSec (Zhao et al., 2014) -- J. Visualization
- Deductive hypothesis-testing on heterogeneous security data
- https://link.springer.com/article/10.1007/s12650-014-0213-6

### GraphQ (Song et al., 2021) -- IEEE VIS/TVCG
- Interactive visual subgraph pattern search using GNNs
- https://arxiv.org/abs/2202.09459

### CyGraph/CyQL (Noel et al., 2016) -- Elsevier
- Domain-specific query language for attack graph patterns with interactive visualization
- Closest precedent to pattern search + arc viz combination
- https://csis.gmu.edu/noel/pubs/2016_Cognitive_Computing_chapter.pdf

### Survey of Vis Systems for Network Security (Shiravi et al., 2012) -- IEEE TVCG
- Comprehensive taxonomy; identifies gap that arc viz + pattern queries would fill
- https://ieeexplore.ieee.org/document/6007132/

### Parallel Arc Diagrams (Hoek, 2019) -- J. Social Structure
- Formal theory for arc diagrams in temporal 2-mode networks
- https://www.cmu.edu/joss/content/articles/volume12/Hoek.pdf

### NetflowVis (2016) -- CDVE/Springer
- ThemeRiver + link-node temporal NetFlow analysis
- https://link.springer.com/chapter/10.1007/978-3-319-46771-9_27

### BANKSAFE (Fischer et al., 2012/2015) -- IEEE VAST
- Multi-resolution web-based large-scale network security VA
- https://ieeexplore.ieee.org/document/6400528/

---

## Key Positioning Observations

1. **BOTection (2020)** is the most direct methodological precedent -- Markov chains over `conn_state` to fingerprint attack types. Ours uses a declarative DSL instead (symbolic/interpretable vs statistical).

2. **Parlanti & Catania (2025)** taxonomy identifies "Inter-Flow Sequential" analysis as having broadest ATT&CK coverage but being least explored -- directly validates our approach as addressing a recognized gap.

3. **STATL (2002) and CEP systems** are the DSL design ancestors. Our existing `->` / `!` / quantifier syntax aligns with CEP conventions.

4. **CyGraph/CyQL (2016)** is the closest precedent for combining a pattern query language with interactive security visualization.

5. **No existing system** combines arc-based temporal flow visualization with a declarative pattern DSL for flow close-type sequences -- this combination is novel.
