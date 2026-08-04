---- MODULE AttestationNonInterference ----
(***************************************************************************)
(* Veritas Mesh -- Attestation Witness Non-Interference, TLA+ model        *)
(*                                                                         *)
(* Status: DRAFT, Phase 1 (spec/formal/, per ROADMAP.md). Companion to     *)
(* AttestationLifecycle.tla, which explicitly leaves zero-knowledge /      *)
(* non-disclosure (spec/THREAT_ANALYSIS.md S6, property 2) unmodeled and   *)
(* says why: it is a computational-indistinguishability property of a     *)
(* real proof system's output distribution, not something a finite-state  *)
(* model checker can establish.                                          *)
(*                                                                         *)
(* THIS MODEL DOES NOT CHANGE THAT. Read this header in full before       *)
(* citing anything below against THREAT_ANALYSIS.md's zero-knowledge      *)
(* property -- doing so would be exactly the kind of overclaim this       *)
(* project's own discipline (STATUS.md, every RFC's Drawbacks section)    *)
(* exists to prevent.                                                    *)
(*                                                                         *)
(* WHAT THIS MODEL ACTUALLY CHECKS, PRECISELY:                            *)
(*                                                                         *)
(* AttestationLifecycle.tla's Verify/verdict logic is written so that no  *)
(* action ever reads a "private witness" value -- only the derived        *)
(* boolean `satisfied` and the Prover's `proofClaim`. That is a claim      *)
(* about the *protocol wiring*: if it is true, then whatever the real     *)
(* private input was (a specific transaction amount, a specific patient   *)
(* record), the wiring itself introduces no channel through which a       *)
(* Verifier's observable outcome could depend on anything beyond the      *)
(* single satisfied-or-not bit and the Prover's claim. This model makes   *)
(* that claim explicit and checks it mechanically, using the standard     *)
(* model-checking technique for this kind of question: self-composition   *)
(* (Barthe et al.) -- introduce an explicit `witness` variable with        *)
(* deliberately non-injective structure (multiple distinct witnesses map   *)
(* to the same `satisfied` bit, so real ambiguity exists in the state      *)
(* space, not merely by omission), and check that the Verifier-observable  *)
(* variables (verdict) can never distinguish two attestations that agree   *)
(* on `satisfied` and `proofClaim` but disagree on `witness`.              *)
(*                                                                         *)
(* WHAT THIS DOES NOT ESTABLISH:                                          *)
(*   - Nothing about the real cryptographic proof object's distribution.  *)
(*     `witness` here is an uninterpreted symbol, not a modeled circuit    *)
(*     input; this says nothing about whether e.g. proof size, timing, or  *)
(*     any real side channel leaks it (see THREAT_ANALYSIS.md S5.4 for     *)
(*     that, which is explicitly out of this model's scope too).           *)
(*   - Nothing about `input_commitment` (core/src/attestation.rs) hiding   *)
(*     its input -- that is a property of the commitment scheme selected   *)
(*     by RFC-0003, inherited by citation once chosen, not modeled here.   *)
(*   - Zero-knowledge in the cryptographic sense (simulatability against   *)
(*     any PPT distinguisher). What is checked is a strictly weaker,       *)
(*     protocol-level analogue: non-interference of one uninterpreted      *)
(*     hidden variable through this specific finite state machine's        *)
(*     wiring. A real proof system could satisfy this model's property     *)
(*     while still leaking information through channels this model has no  *)
(*     variables to represent (proof byte length varying with witness      *)
(*     magnitude, for instance -- exactly the risk flagged in              *)
(*     THREAT_ANALYSIS.md S5.4).                                          *)
(*                                                                         *)
(* Why build this anyway: it is a real, if narrow, thing to check, and it  *)
(* is the kind of protocol-level interaction spec/formal/README.md's "What *)
(* comes next" section names as in-scope once a proof system-independent   *)
(* wiring check is worth doing on its own. It also gives RFC-0002 and      *)
(* RFC-0003 authors a concrete non-interference bar the eventual proof and *)
(* commitment layer's *integration* into `core/` should not regress below, *)
(* independent of whatever zero-knowledge guarantee the chosen primitive   *)
(* itself provides.                                                       *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Attestations,       \* symbolic set of attestation instances under study
    Verifiers,           \* symbolic set of independent verifiers
    Malicious            \* subset of Attestations whose Prover is modeled as adversarial

ASSUME Malicious \subseteq Attestations

Phases == {"Init", "InputsComputed", "ProofGenerated", "Signed", "Published"}

\* Witnesses and their satisfaction mapping are fixed operators, not model
\* constants: this is a small, closed illustrative domain (four witness
\* values, two per truth value), not something a caller needs to vary per
\* run, and defining it here avoids TLC .cfg's more fragile syntax for
\* function-valued CONSTANTS.
Witnesses == {"w1", "w2", "w3", "w4"}
WitnessSatisfies == [w \in Witnesses |-> w \in {"w1", "w2"}]

ASSUME WitnessSatisfies \in [Witnesses -> BOOLEAN]

VARIABLES
    phase,          \* [Attestations -> Phases]
    witness,        \* [Attestations -> Witnesses]  the (hidden) private input, chosen
                     \* non-deterministically at ComputeInputs time
    satisfied,      \* [Attestations -> BOOLEAN]  derived: WitnessSatisfies[witness[a]]
    proofClaim,     \* [Attestations -> BOOLEAN]  the bit the generated proof asserts
    signed,         \* [Attestations -> BOOLEAN]
    verdict         \* [Verifiers -> [Attestations -> {"Unchecked","Accept","Reject"}]]

vars == <<phase, witness, satisfied, proofClaim, signed, verdict>>

TypeOK ==
    /\ phase \in [Attestations -> Phases]
    /\ witness \in [Attestations -> Witnesses]
    /\ satisfied \in [Attestations -> BOOLEAN]
    /\ proofClaim \in [Attestations -> BOOLEAN]
    /\ signed \in [Attestations -> BOOLEAN]
    /\ verdict \in [Verifiers -> [Attestations -> {"Unchecked", "Accept", "Reject"}]]

Init ==
    /\ phase = [a \in Attestations |-> "Init"]
    /\ witness \in [Attestations -> Witnesses]
    /\ satisfied = [a \in Attestations |-> WitnessSatisfies[witness[a]]]
    /\ proofClaim = [a \in Attestations |-> FALSE]
    /\ signed = [a \in Attestations |-> FALSE]
    /\ verdict = [v \in Verifiers |-> [a \in Attestations |-> "Unchecked"]]

(* PROTOCOL_SPEC.md S5 step 2: private computation.
   The witness is (re-)chosen here and never touched again -- no later action
   reads or writes `witness`, only the already-derived `satisfied` bit. This
   is the syntactic fact the rest of the model exists to make TLC confirm has
   no observable consequence, not merely assert by inspection. *)
ComputeInputs(a) ==
    /\ phase[a] = "Init"
    /\ phase' = [phase EXCEPT ![a] = "InputsComputed"]
    /\ \E w \in Witnesses :
        /\ witness' = [witness EXCEPT ![a] = w]
        /\ satisfied' = [satisfied EXCEPT ![a] = WitnessSatisfies[w]]
    /\ UNCHANGED <<proofClaim, signed, verdict>>

(* PROTOCOL_SPEC.md S5 step 3: proof generation. Identical logic to
   AttestationLifecycle.tla -- references `satisfied`, never `witness`. *)
GenerateProof(a) ==
    /\ phase[a] = "InputsComputed"
    /\ phase' = [phase EXCEPT ![a] = "ProofGenerated"]
    /\ proofClaim' = [proofClaim EXCEPT ![a] =
                        IF a \in Malicious
                        THEN TRUE
                        ELSE satisfied[a]]
    /\ UNCHANGED <<witness, satisfied, signed, verdict>>

(* PROTOCOL_SPEC.md S5 step 4: attestation assembly and signing. *)
Sign(a) ==
    /\ phase[a] = "ProofGenerated"
    /\ phase' = [phase EXCEPT ![a] = "Signed"]
    /\ signed' = [signed EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<witness, satisfied, proofClaim, verdict>>

(* PROTOCOL_SPEC.md S5 step 5: publication. *)
Publish(a) ==
    /\ phase[a] = "Signed"
    /\ phase' = [phase EXCEPT ![a] = "Published"]
    /\ UNCHANGED <<witness, satisfied, proofClaim, signed, verdict>>

(* PROTOCOL_SPEC.md S5 step 6: verification. Identical formula to
   AttestationLifecycle.tla: a pure function of (proofClaim, satisfied) --
   `witness` does not, and per TypeOK cannot meaningfully, appear here. *)
Verify(v, a) ==
    /\ phase[a] = "Published"
    /\ verdict[v][a] = "Unchecked"
    /\ signed[a] = TRUE
    /\ verdict' = [verdict EXCEPT ![v][a] =
                     IF proofClaim[a] = TRUE /\ proofClaim[a] = satisfied[a]
                     THEN "Accept"
                     ELSE "Reject"]
    /\ UNCHANGED <<phase, witness, satisfied, proofClaim, signed>>

Next ==
    \/ \E a \in Attestations : ComputeInputs(a)
    \/ \E a \in Attestations : GenerateProof(a)
    \/ \E a \in Attestations : Sign(a)
    \/ \E a \in Attestations : Publish(a)
    \/ \E v \in Verifiers, a \in Attestations : Verify(v, a)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* Properties ported from AttestationLifecycle.tla, re-checked over a state
   space that now includes genuine witness ambiguity (Witnesses/
   WitnessSatisfies above are fixed so two distinct witnesses map to each
   truth value). Holding here shows these two properties are robust to that
   ambiguity, not merely true in the simpler boolean-only model. *)

SoundnessLifecycle ==
    \A v \in Verifiers, a \in Attestations :
        verdict[v][a] = "Accept" => satisfied[a] = TRUE

MultiVerifierIndependence ==
    \A v1, v2 \in Verifiers, a \in Attestations :
        (verdict[v1][a] # "Unchecked" /\ verdict[v2][a] # "Unchecked")
            => verdict[v1][a] = verdict[v2][a]

EventuallyPublished ==
    \A a \in Attestations : <>(phase[a] = "Published")

(* The property this model exists to add. See header for exactly what it
   does and does not establish. Precisely: any two attestations that agree
   on ground truth (`satisfied`) and on the Prover's claim (`proofClaim`)
   must receive the same verdict from a given Verifier, even when their
   underlying `witness` values differ -- i.e. `witness` is not, and per the
   action formulas above structurally cannot be, an input to `verdict`. *)
WitnessNonInterference ==
    \A v \in Verifiers, a, b \in Attestations :
        (/\ verdict[v][a] # "Unchecked"
         /\ verdict[v][b] # "Unchecked"
         /\ satisfied[a] = satisfied[b]
         /\ proofClaim[a] = proofClaim[b])
            => verdict[v][a] = verdict[v][b]

(* NOTE on witness ambiguity: this model does not add a TLC-checked
   "ambiguity is reachable" property. An eventually-formula like
   `<>(\E a,b : satisfied[a]=satisfied[b] /\ witness[a]#witness[b])` is not
   a validity -- some fair behaviors legitimately never hit that
   configuration (e.g. one where nondeterministic witness choice happens to
   coincide for every pair) -- so TLC would correctly reject it as a
   PROPERTY, and it would be the wrong tool here regardless: it would only
   confirm SOME behavior exercises ambiguity, not that TLC's invariant
   checks above ran against ambiguous states specifically. What actually
   establishes that is combinatorial and stated in
   AttestationNonInterference_report.md: `Init`'s
   `\E w \in Witnesses : witness' = [witness EXCEPT ![a] = w]` ranges
   independently per attestation over the full four-element `Witnesses` set
   defined above (deliberately sized so two witnesses map to each truth
   value), so TLC's exhaustive (not sampled) state-space search necessarily
   visits states with `witness[a] # witness[b] /\ satisfied[a] = satisfied[b]`
   -- and `WitnessNonInterference` above is checked, by TLC's own semantics,
   against every reachable state, ambiguous ones included. *)
====
