---- MODULE AttestationLifecycle ----
(***************************************************************************)
(* Veritas Mesh -- Attestation Lifecycle, TLA+ model                       *)
(*                                                                         *)
(* Status: DRAFT, Phase 1 (spec/formal/, per ROADMAP.md).                  *)
(*                                                                         *)
(* Models the six-step lifecycle normatively defined in                   *)
(* spec/PROTOCOL_SPEC.md Section 5:                                       *)
(*   1. Rule publication      (folded into Init -- out of scope here,     *)
(*                              governed separately by GOVERNANCE.md)     *)
(*   2. Private computation    -> ComputeInputs                           *)
(*   3. Proof generation       -> GenerateProof                           *)
(*   4. Attestation assembly   -> Sign                                    *)
(*      and signing                                                       *)
(*   5. Publication             -> Publish                                *)
(*   6. Verification            -> Verify                                 *)
(*                                                                         *)
(* IMPORTANT SCOPE CAVEAT -- read before citing any result from this file *)
(* against the three target properties in spec/THREAT_ANALYSIS.md S5:     *)
(*                                                                         *)
(* This model treats the correctness of the (not-yet-selected, see        *)
(* rfcs/0002-proof-system-selection.md) cryptographic proof system as an  *)
(* AXIOM, not something it establishes. Concretely: GenerateProof forbids *)
(* an honestly-modeled Prover from producing a proofClaim that disagrees  *)
(* with ground truth, which is exactly the soundness property that a real *)
(* SNARK/STARK construction is supposed to guarantee computationally, not *)
(* something a finite-state model can prove about an actual cryptosystem. *)
(*                                                                         *)
(* What this model DOES meaningfully check, given that axiom:             *)
(*   - SoundnessLifecycle: nothing in the *protocol wiring itself* (state  *)
(*     ordering, signing, publication) introduces an additional bypass    *)
(*     that would let a false claim reach "Accept" even when the          *)
(*     underlying crypto primitive is sound.                              *)
(*   - MultiVerifierIndependence: verification is wired as a pure         *)
(*     function of public attestation state, so independent verifiers     *)
(*     can never be steered to disagree on the same attestation.          *)
(*                                                                         *)
(* What this model does NOT check, and cannot check by this method:       *)
(*   - Zero-knowledge / non-disclosure (THREAT_ANALYSIS.md S5, property 2)*)
(*     is a computational-indistinguishability property of the proof      *)
(*     system itself, not of the lifecycle state machine. It has no       *)
(*     representation here (proofClaim is a bare boolean, not a proof     *)
(*     object with a distribution to analyze) and must be established by  *)
(*     whichever concrete SNARK/STARK construction RFC-0002 selects,      *)
(*     citing that construction's own published security proof.          *)
(*   - The real cryptographic soundness bound (negligible-probability      *)
(*     forgery) -- that is a property of the selected proof system, to be *)
(*     inherited by reference, not re-derived here.                       *)
(*                                                                         *)
(* This caveat is restated in AttestationLifecycle_report.md and should   *)
(* travel with any summary of these results.                             *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS
    Attestations,   \* symbolic set of attestation instances under study, e.g. {a1, a2}
    Verifiers,      \* symbolic set of independent verifiers, e.g. {v1, v2}
    Malicious       \* subset of Attestations whose Prover is modeled as adversarial

ASSUME Malicious \subseteq Attestations

Phases == {"Init", "InputsComputed", "ProofGenerated", "Signed", "Published"}

VARIABLES
    phase,          \* [Attestations -> Phases]
    satisfied,      \* [Attestations -> BOOLEAN]  ground truth: were the private inputs
                     \* actually consistent with the rule module R_id@version?
    proofClaim,     \* [Attestations -> BOOLEAN]  the bit the generated proof asserts
    signed,         \* [Attestations -> BOOLEAN]
    verdict         \* [Verifiers -> [Attestations -> {"Unchecked","Accept","Reject"}]]

vars == <<phase, satisfied, proofClaim, signed, verdict>>

TypeOK ==
    /\ phase \in [Attestations -> Phases]
    /\ satisfied \in [Attestations -> BOOLEAN]
    /\ proofClaim \in [Attestations -> BOOLEAN]
    /\ signed \in [Attestations -> BOOLEAN]
    /\ verdict \in [Verifiers -> [Attestations -> {"Unchecked", "Accept", "Reject"}]]

Init ==
    /\ phase = [a \in Attestations |-> "Init"]
    /\ satisfied \in [Attestations -> BOOLEAN]
    /\ proofClaim = [a \in Attestations |-> FALSE]
    /\ signed = [a \in Attestations |-> FALSE]
    /\ verdict = [v \in Verifiers |-> [a \in Attestations |-> "Unchecked"]]

(* PROTOCOL_SPEC.md S5 step 2: private computation. *)
ComputeInputs(a) ==
    /\ phase[a] = "Init"
    /\ phase' = [phase EXCEPT ![a] = "InputsComputed"]
    /\ UNCHANGED <<satisfied, proofClaim, signed, verdict>>

(* PROTOCOL_SPEC.md S5 step 3: proof generation.
   See the file header for exactly what is, and is not, being assumed here. *)
GenerateProof(a) ==
    /\ phase[a] = "InputsComputed"
    /\ phase' = [phase EXCEPT ![a] = "ProofGenerated"]
    /\ proofClaim' = [proofClaim EXCEPT ![a] =
                        IF a \in Malicious
                        THEN TRUE   \* worst case: adversarial Prover always attempts to
                                    \* claim satisfaction regardless of ground truth
                        ELSE satisfied[a]]
    /\ UNCHANGED <<satisfied, signed, verdict>>

(* PROTOCOL_SPEC.md S5 step 4: attestation assembly and signing. *)
Sign(a) ==
    /\ phase[a] = "ProofGenerated"
    /\ phase' = [phase EXCEPT ![a] = "Signed"]
    /\ signed' = [signed EXCEPT ![a] = TRUE]
    /\ UNCHANGED <<satisfied, proofClaim, verdict>>

(* PROTOCOL_SPEC.md S5 step 5: publication to the mesh network or direct delivery. *)
Publish(a) ==
    /\ phase[a] = "Signed"
    /\ phase' = [phase EXCEPT ![a] = "Published"]
    /\ UNCHANGED <<satisfied, proofClaim, signed, verdict>>

(* PROTOCOL_SPEC.md S5 step 6: verification.
   Modeled as a pure function of public attestation state only -- no verifier
   identity, no private input, per Design Constraints 1-2 in PROTOCOL_SPEC.md S2. *)
Verify(v, a) ==
    /\ phase[a] = "Published"
    /\ verdict[v][a] = "Unchecked"
    /\ signed[a] = TRUE
    /\ verdict' = [verdict EXCEPT ![v][a] =
                     IF proofClaim[a] = TRUE /\ proofClaim[a] = satisfied[a]
                     THEN "Accept"
                     ELSE "Reject"]
    /\ UNCHANGED <<phase, satisfied, proofClaim, signed>>

Next ==
    \/ \E a \in Attestations : ComputeInputs(a)
    \/ \E a \in Attestations : GenerateProof(a)
    \/ \E a \in Attestations : Sign(a)
    \/ \E a \in Attestations : Publish(a)
    \/ \E v \in Verifiers, a \in Attestations : Verify(v, a)

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* Target properties -- see spec/THREAT_ANALYSIS.md Section 5.
   Read the file header before citing these; only two of the three named
   properties are represented here, under an explicit soundness axiom. *)

(* Soundness, lifecycle-wiring sketch only (see header caveat). *)
SoundnessLifecycle ==
    \A v \in Verifiers, a \in Attestations :
        verdict[v][a] = "Accept" => satisfied[a] = TRUE

(* Multi-verifier independence -- PROTOCOL_SPEC.md S2, Design Constraint 3. *)
MultiVerifierIndependence ==
    \A v1, v2 \in Verifiers, a \in Attestations :
        (verdict[v1][a] # "Unchecked" /\ verdict[v2][a] # "Unchecked")
            => verdict[v1][a] = verdict[v2][a]

(* Liveness sanity check (not a security property): the lifecycle as wired
   does not deadlock before every attestation reaches Published. *)
EventuallyPublished ==
    \A a \in Attestations : <>(phase[a] = "Published")

====
