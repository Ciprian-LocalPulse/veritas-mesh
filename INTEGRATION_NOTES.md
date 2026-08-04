# Integration notes — RFCs 0001-0003 + spec/formal/ Phase 1 draft

Acest pachet conține fișierele care lipseau, respectând procesul pe care
tu însuți l-ai stabilit în `GOVERNANCE.md`, `ROADMAP.md` și README-urile
din `core/`, `sdk/`, `spec/formal/` — adică pașii care vin *înainte* de
implementare, nu cod prematur.

## Ce conține

```
rfcs/
├── 0001-attestation-format-finalization.md
├── 0002-proof-system-selection.md
├── 0003-commitment-scheme-selection.md
└── README.md                              (înlocuiește pe cel existent)

spec/formal/
├── AttestationLifecycle.tla
├── AttestationLifecycle.cfg
├── AttestationLifecycle_report.md
├── tlc_run.log                            (rulare reală, TLC2 v2.19)
└── README.md                              (înlocuiește pe cel existent)
```

## Cum integrezi în `VERITAS-MESH`

```powershell
# din C:\Users\saint\OneDrive\Desktop\VERITAS-MESH
Copy-Item -Path "<unzip-path>\rfcs\*" -Destination ".\rfcs\" -Force
Copy-Item -Path "<unzip-path>\spec\formal\*" -Destination ".\spec\formal\" -Force

git add rfcs spec/formal
git commit -m "rfcs: propose 0001-0003 (format, proof system, commitment scheme); spec/formal: Phase 1 lifecycle model + TLC results"
git push origin main
```

## Ce trebuie să știi înainte să dai push

1. **RFC-urile sunt Draft, nu acceptate.** Am respectat exact regula din
   `GOVERNANCE.md`: un RFC devine "acceptat" doar după perioada minimă de
   discuție pe un pull request public. Nu am bifat nimic în `ROADMAP.md`
   — primele două căsuțe de la Phase 0 ("First round of public RFC
   discussion...") rămân nebifate corect, până deschizi efectiv discuția.
2. **Modelul TLA+ a fost rulat cu adevărat**, nu doar scris — vezi
   `spec/formal/tlc_run.log` pentru output-ul brut de la TLC (256 de stări
   distincte explorate, fără erori). Asta respectă regula pe care ai
   scris-o chiar tu în `spec/formal/README.md`: niciun fișier nu intră
   acolo fără să fi trecut printr-un model checker cu rezultatele incluse.
3. **Modelul acoperă doar 2 din 3 proprietăți țintă** din
   `THREAT_ANALYSIS.md` §6 — soundness-ul "cablajului" protocolului și
   independența multi-verificator. Zero-knowledge/non-disclosure rămâne
   deschis, corect, pentru că e o proprietate a sistemului de proof
   criptografic ales (RFC 0002), nu ceva ce un model de stări finite poate
   verifica. Asta e explicat pe larg în `AttestationLifecycle_report.md`
   — merită citit înainte să postezi rezultatele undeva public, ca să nu
   pară o supra-promisiune.
4. **`core/`, `mesh/`, `dashboard/`, `sdk/` rămân goale.** Corect, conform
   propriei tale reguli — RFC 0002 și 0003 trebuie discutate și acceptate
   public înainte ca cineva să poată deschide un PR substanțial acolo.

## Pasul următor logic

Deschide RFC 0001 ca pull request separat (cu discuția publică), apoi
0002, apoi 0003 (0003 depinde de rezultatul lui 0002, e explicat în
motivația lui). După ce trec de perioada minimă de discuție din
`GOVERNANCE.md`, le poți marca "Accepted" și abia atunci se deblochează,
conform propriilor tale reguli, munca de implementare din `core/`.
