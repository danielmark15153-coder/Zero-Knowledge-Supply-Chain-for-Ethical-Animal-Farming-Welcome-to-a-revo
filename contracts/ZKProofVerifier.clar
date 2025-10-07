(define-constant ERR_INVALID_PROOF u100)
(define-constant ERR_NOT_AUTHORIZED u101)
(define-constant ERR_ALREADY_VERIFIED u102)
(define-constant ERR_PROOF_NOT_FOUND u103)
(define-constant ERR_INVALID_PROOF_TYPE u104)
(define-constant ERR_INVALID_PROOF_DATA u105)
(define-constant ERR_INVALID_SUBMITTER u106)
(define-constant ERR_INVALID_TIMESTAMP u107)
(define-constant ERR_VERIFIER_NOT_SET u108)
(define-constant ERR_INVALID_CATEGORY u109)
(define-constant ERR_PROOF_EXPIRED u110)
(define-constant ERR_INVALID_CHALLENGE u111)
(define-constant ERR_CHALLENGE_MISMATCH u112)
(define-constant ERR_INVALID_SIGNATURE u113)
(define-constant ERR_MAX_PROOFS_EXCEEDED u114)
(define-constant ERR_INVALID_EXPIRY u115)
(define-constant ERR_INVALID_BATCH_SIZE u116)
(define-constant ERR_BATCH_ALREADY_PROCESSED u117)
(define-constant ERR_INVALID_VERIFICATION_KEY u118)
(define-constant ERR_ACCESS_DENIED u119)
(define-constant ERR_SYSTEM_PAUSED u120)

(define-data-var verifier-principal principal tx-sender)
(define-data-var system-paused bool false)
(define-data-var max-proofs uint u10000)
(define-data-var proof-count uint u0)
(define-data-var default-expiry uint u144)
(define-data-var admin-principal principal tx-sender)

(define-map Proofs
  { proof-id: (buff 32) }
  {
    submitter: principal,
    timestamp: uint,
    is-valid: bool,
    proof-type: (string-ascii 32),
    category: (string-ascii 32),
    expiry: uint,
    challenge: (buff 32),
    signature: (buff 64)
  }
)

(define-map BatchProofs
  { batch-id: (buff 32) }
  {
    proofs: (list 10 (buff 32)),
    processed: bool,
    verifier: principal,
    timestamp: uint
  }
)

(define-map VerificationKeys
  { key-id: (buff 32) }
  { key-data: (buff 256), owner: principal }
)

(define-read-only (get-proof (proof-id (buff 32)))
  (map-get? Proofs { proof-id: proof-id })
)

(define-read-only (get-batch (batch-id (buff 32)))
  (map-get? BatchProofs { batch-id: batch-id })
)

(define-read-only (get-verification-key (key-id (buff 32)))
  (map-get? VerificationKeys { key-id: key-id })
)

(define-read-only (get-proof-count)
  (ok (var-get proof-count))
)

(define-read-only (is-system-paused)
  (ok (var-get system-paused))
)

(define-private (validate-proof-type (proof-type (string-ascii 32)))
  (if (or (is-eq proof-type "snark") (is-eq proof-type "stark") (is-eq proof-type "bulletproof"))
    (ok true)
    (err ERR_INVALID_PROOF_TYPE))
)

(define-private (validate-category (category (string-ascii 32)))
  (if (or (is-eq category "humane") (is-eq category "feed") (is-eq category "transport") (is-eq category "health"))
    (ok true)
    (err ERR_INVALID_CATEGORY))
)

(define-private (validate-proof-data (proof-data (buff 256)))
  (if (> (len proof-data) u0)
    (ok true)
    (err ERR_INVALID_PROOF_DATA))
)

(define-private (validate-submitter (submitter principal))
  (if (not (is-eq submitter 'SP000000000000000000002Q6VF78))
    (ok true)
    (err ERR_INVALID_SUBMITTER))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
    (ok true)
    (err ERR_INVALID_TIMESTAMP))
)

(define-private (validate-expiry (expiry uint))
  (if (> expiry u0)
    (ok true)
    (err ERR_INVALID_EXPIRY))
)

(define-private (validate-challenge (challenge (buff 32)))
  (if (is-eq (len challenge) u32)
    (ok true)
    (err ERR_INVALID_CHALLENGE))
)

(define-private (validate-signature (signature (buff 64)))
  (if (is-eq (len signature) u64)
    (ok true)
    (err ERR_INVALID_SIGNATURE))
)

(define-private (validate-batch-size (size uint))
  (if (and (> size u0) (<= size u10))
    (ok true)
    (err ERR_INVALID_BATCH_SIZE))
)

(define-private (validate-verification-key (key-data (buff 256)))
  (if (> (len key-data) u0)
    (ok true)
    (err ERR_INVALID_VERIFICATION_KEY))
)

(define-private (is-valid-zkp (proof-data (buff 256)) (key-id (buff 32)))
  (match (map-get? VerificationKeys { key-id: key-id })
    key
      (if (is-eq (get owner key) tx-sender)
        true
        false)
    false)
)

(define-public (set-verifier-principal (new-verifier principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR_NOT_AUTHORIZED))
    (try! (validate-submitter new-verifier))
    (var-set verifier-principal new-verifier)
    (ok true)
  )
)

(define-public (pause-system (pause bool))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR_NOT_AUTHORIZED))
    (var-set system-paused pause)
    (ok true)
  )
)

(define-public (set-max-proofs (new-max uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR_NOT_AUTHORIZED))
    (asserts! (> new-max u0) (err ERR_MAX_PROOFS_EXCEEDED))
    (var-set max-proofs new-max)
    (ok true)
  )
)

(define-public (set-default-expiry (new-expiry uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR_NOT_AUTHORIZED))
    (try! (validate-expiry new-expiry))
    (var-set default-expiry new-expiry)
    (ok true)
  )
)

(define-public (register-verification-key (key-id (buff 32)) (key-data (buff 256)))
  (begin
    (asserts! (is-eq tx-sender (var-get verifier-principal)) (err ERR_NOT_AUTHORIZED))
    (try! (validate-verification-key key-data))
    (asserts! (is-none (map-get? VerificationKeys { key-id: key-id })) (err ERR_ALREADY_VERIFIED))
    (map-set VerificationKeys { key-id: key-id } { key-data: key-data, owner: tx-sender })
    (ok true)
  )
)

(define-public (submit-proof 
  (proof-id (buff 32)) 
  (proof-data (buff 256)) 
  (proof-type (string-ascii 32)) 
  (category (string-ascii 32)) 
  (expiry uint) 
  (challenge (buff 32)) 
  (signature (buff 64))
  (key-id (buff 32)))
  (let
    (
      (submitter tx-sender)
      (current-count (var-get proof-count))
      (existing-proof (map-get? Proofs { proof-id: proof-id }))
    )
    (asserts! (not (var-get system-paused)) (err ERR_SYSTEM_PAUSED))
    (asserts! (< current-count (var-get max-proofs)) (err ERR_MAX_PROOFS_EXCEEDED))
    (asserts! (is-none existing-proof) (err ERR_ALREADY_VERIFIED))
    (try! (validate-proof-type proof-type))
    (try! (validate-category category))
    (try! (validate-proof-data proof-data))
    (try! (validate-submitter submitter))
    (try! (validate-expiry expiry))
    (try! (validate-challenge challenge))
    (try! (validate-signature signature))
    (asserts! (is-valid-zkp proof-data key-id) (err ERR_INVALID_PROOF))
    (map-set Proofs
      { proof-id: proof-id }
      {
        submitter: submitter,
        timestamp: block-height,
        is-valid: true,
        proof-type: proof-type,
        category: category,
        expiry: (+ block-height expiry),
        challenge: challenge,
        signature: signature
      }
    )
    (var-set proof-count (+ current-count u1))
    (print { event: "proof-submitted", id: proof-id })
    (ok true)
  )
)

(define-public (verify-proof (proof-id (buff 32)) (challenge (buff 32)))
  (match (map-get? Proofs { proof-id: proof-id })
    proof
      (begin
        (asserts! (is-eq (get submitter proof) tx-sender) (err ERR_ACCESS_DENIED))
        (asserts! (> (get expiry proof) block-height) (err ERR_PROOF_EXPIRED))
        (asserts! (is-eq (get challenge proof) challenge) (err ERR_CHALLENGE_MISMATCH))
        (ok (get is-valid proof))
      )
    (err ERR_PROOF_NOT_FOUND)
  )
)

(define-public (submit-batch-proofs 
  (batch-id (buff 32)) 
  (proof-ids (list 10 (buff 32))) 
  (key-id (buff 32)))
  (let
    (
      (size (len proof-ids))
      (existing-batch (map-get? BatchProofs { batch-id: batch-id }))
    )
    (asserts! (not (var-get system-paused)) (err ERR_SYSTEM_PAUSED))
    (try! (validate-batch-size size))
    (asserts! (is-none existing-batch) (err ERR_BATCH_ALREADY_PROCESSED))
    (asserts! (is-eq tx-sender (var-get verifier-principal)) (err ERR_NOT_AUTHORIZED))
    (fold process-batch-proof proof-ids (ok true))
    (map-set BatchProofs
      { batch-id: batch-id }
      {
        proofs: proof-ids,
        processed: true,
        verifier: tx-sender,
        timestamp: block-height
      }
    )
    (print { event: "batch-processed", id: batch-id })
    (ok true)
  )
)

(define-private (process-batch-proof (proof-id (buff 32)) (acc (response bool uint)))
  (match acc
    success
      (match (map-get? Proofs { proof-id: proof-id })
        proof
          (if (get is-valid proof)
            (ok true)
            (err ERR_INVALID_PROOF))
        (err ERR_PROOF_NOT_FOUND))
    error error
  )
)

(define-public (revoke-proof (proof-id (buff 32)))
  (match (map-get? Proofs { proof-id: proof-id })
    proof
      (begin
        (asserts! (or (is-eq tx-sender (get submitter proof)) (is-eq tx-sender (var-get admin-principal))) (err ERR_NOT_AUTHORIZED))
        (map-set Proofs { proof-id: proof-id } (merge proof { is-valid: false }))
        (print { event: "proof-revoked", id: proof-id })
        (ok true)
      )
    (err ERR_PROOF_NOT_FOUND)
  )
)

(define-public (update-proof-expiry (proof-id (buff 32)) (new-expiry uint))
  (match (map-get? Proofs { proof-id: proof-id })
    proof
      (begin
        (asserts! (is-eq tx-sender (get submitter proof)) (err ERR_NOT_AUTHORIZED))
        (try! (validate-expiry new-expiry))
        (map-set Proofs { proof-id: proof-id } (merge proof { expiry: (+ block-height new-expiry) }))
        (ok true)
      )
    (err ERR_PROOF_NOT_FOUND)
  )
)