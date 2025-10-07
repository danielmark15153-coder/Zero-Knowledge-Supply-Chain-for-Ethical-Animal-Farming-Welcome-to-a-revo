import { describe, it, expect, beforeEach } from "vitest";
import { buffCV, stringAsciiCV, uintCV } from "@stacks/transactions";

const ERR_INVALID_PROOF = 100;
const ERR_NOT_AUTHORIZED = 101;
const ERR_ALREADY_VERIFIED = 102;
const ERR_PROOF_NOT_FOUND = 103;
const ERR_INVALID_PROOF_TYPE = 104;
const ERR_INVALID_PROOF_DATA = 105;
const ERR_INVALID_SUBMITTER = 106;
const ERR_INVALID_TIMESTAMP = 107;
const ERR_VERIFIER_NOT_SET = 108;
const ERR_INVALID_CATEGORY = 109;
const ERR_PROOF_EXPIRED = 110;
const ERR_INVALID_CHALLENGE = 111;
const ERR_CHALLENGE_MISMATCH = 112;
const ERR_INVALID_SIGNATURE = 113;
const ERR_MAX_PROOFS_EXCEEDED = 114;
const ERR_INVALID_EXPIRY = 115;
const ERR_INVALID_BATCH_SIZE = 116;
const ERR_BATCH_ALREADY_PROCESSED = 117;
const ERR_INVALID_VERIFICATION_KEY = 118;
const ERR_ACCESS_DENIED = 119;
const ERR_SYSTEM_PAUSED = 120;

interface Proof {
  submitter: string;
  timestamp: number;
  isValid: boolean;
  proofType: string;
  category: string;
  expiry: number;
  challenge: Uint8Array;
  signature: Uint8Array;
}

interface BatchProof {
  proofs: Uint8Array[];
  processed: boolean;
  verifier: string;
  timestamp: number;
}

interface VerificationKey {
  keyData: Uint8Array;
  owner: string;
}

interface Result<T, E> {
  ok: boolean;
  value: T | E;
}

class ZKProofVerifierMock {
  state: {
    verifierPrincipal: string;
    systemPaused: boolean;
    maxProofs: number;
    proofCount: number;
    defaultExpiry: number;
    adminPrincipal: string;
    proofs: Map<string, Proof>;
    batchProofs: Map<string, BatchProof>;
    verificationKeys: Map<string, VerificationKey>;
  } = {
    verifierPrincipal: "ST1TEST",
    systemPaused: false,
    maxProofs: 10000,
    proofCount: 0,
    defaultExpiry: 144,
    adminPrincipal: "ST1TEST",
    proofs: new Map(),
    batchProofs: new Map(),
    verificationKeys: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1TEST";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      verifierPrincipal: "ST1TEST",
      systemPaused: false,
      maxProofs: 10000,
      proofCount: 0,
      defaultExpiry: 144,
      adminPrincipal: "ST1TEST",
      proofs: new Map(),
      batchProofs: new Map(),
      verificationKeys: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1TEST";
  }

  getProof(proofId: Uint8Array): Result<Proof | null, number> {
    const key = proofId.toString();
    return { ok: true, value: this.state.proofs.get(key) || null };
  }

  getBatch(batchId: Uint8Array): Result<BatchProof | null, number> {
    const key = batchId.toString();
    return { ok: true, value: this.state.batchProofs.get(key) || null };
  }

  getVerificationKey(keyId: Uint8Array): Result<VerificationKey | null, number> {
    const key = keyId.toString();
    return { ok: true, value: this.state.verificationKeys.get(key) || null };
  }

  getProofCount(): Result<number, number> {
    return { ok: true, value: this.state.proofCount };
  }

  isSystemPaused(): Result<boolean, number> {
    return { ok: true, value: this.state.systemPaused };
  }

  setVerifierPrincipal(newVerifier: string): Result<boolean, number> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newVerifier === "SP000000000000000000002Q6VF78") return { ok: false, value: ERR_INVALID_SUBMITTER };
    this.state.verifierPrincipal = newVerifier;
    return { ok: true, value: true };
  }

  pauseSystem(pause: boolean): Result<boolean, number> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.systemPaused = pause;
    return { ok: true, value: true };
  }

  setMaxProofs(newMax: number): Result<boolean, number> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newMax <= 0) return { ok: false, value: ERR_MAX_PROOFS_EXCEEDED };
    this.state.maxProofs = newMax;
    return { ok: true, value: true };
  }

  setDefaultExpiry(newExpiry: number): Result<boolean, number> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newExpiry <= 0) return { ok: false, value: ERR_INVALID_EXPIRY };
    this.state.defaultExpiry = newExpiry;
    return { ok: true, value: true };
  }

  registerVerificationKey(keyId: Uint8Array, keyData: Uint8Array): Result<boolean, number> {
    if (this.caller !== this.state.verifierPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (keyData.length === 0) return { ok: false, value: ERR_INVALID_VERIFICATION_KEY };
    const key = keyId.toString();
    if (this.state.verificationKeys.has(key)) return { ok: false, value: ERR_ALREADY_VERIFIED };
    this.state.verificationKeys.set(key, { keyData, owner: this.caller });
    return { ok: true, value: true };
  }

  submitProof(
    proofId: Uint8Array,
    proofData: Uint8Array,
    proofType: string,
    category: string,
    expiry: number,
    challenge: Uint8Array,
    signature: Uint8Array,
    keyId: Uint8Array
  ): Result<boolean, number> {
    if (this.state.systemPaused) return { ok: false, value: ERR_SYSTEM_PAUSED };
    if (this.state.proofCount >= this.state.maxProofs) return { ok: false, value: ERR_MAX_PROOFS_EXCEEDED };
    const key = proofId.toString();
    if (this.state.proofs.has(key)) return { ok: false, value: ERR_ALREADY_VERIFIED };
    if (!["snark", "stark", "bulletproof"].includes(proofType)) return { ok: false, value: ERR_INVALID_PROOF_TYPE };
    if (!["humane", "feed", "transport", "health"].includes(category)) return { ok: false, value: ERR_INVALID_CATEGORY };
    if (proofData.length === 0) return { ok: false, value: ERR_INVALID_PROOF_DATA };
    if (this.caller === "SP000000000000000000002Q6VF78") return { ok: false, value: ERR_INVALID_SUBMITTER };
    if (expiry <= 0) return { ok: false, value: ERR_INVALID_EXPIRY };
    if (challenge.length !== 32) return { ok: false, value: ERR_INVALID_CHALLENGE };
    if (signature.length !== 64) return { ok: false, value: ERR_INVALID_SIGNATURE };
    const vKey = keyId.toString();
    const verificationKey = this.state.verificationKeys.get(vKey);
    if (!verificationKey || verificationKey.owner !== this.caller) return { ok: false, value: ERR_INVALID_PROOF };
    this.state.proofs.set(key, {
      submitter: this.caller,
      timestamp: this.blockHeight,
      isValid: true,
      proofType,
      category,
      expiry: this.blockHeight + expiry,
      challenge,
      signature,
    });
    this.state.proofCount++;
    return { ok: true, value: true };
  }

  verifyProof(proofId: Uint8Array, challenge: Uint8Array): Result<boolean, number> {
    const key = proofId.toString();
    const proof = this.state.proofs.get(key);
    if (!proof) return { ok: false, value: ERR_PROOF_NOT_FOUND };
    if (proof.submitter !== this.caller) return { ok: false, value: ERR_ACCESS_DENIED };
    if (proof.expiry <= this.blockHeight) return { ok: false, value: ERR_PROOF_EXPIRED };
    if (!this.arrayEquals(proof.challenge, challenge)) return { ok: false, value: ERR_CHALLENGE_MISMATCH };
    return { ok: true, value: proof.isValid };
  }

  submitBatchProofs(batchId: Uint8Array, proofIds: Uint8Array[], keyId: Uint8Array): Result<boolean, number> {
    if (this.state.systemPaused) return { ok: false, value: ERR_SYSTEM_PAUSED };
    if (proofIds.length === 0 || proofIds.length > 10) return { ok: false, value: ERR_INVALID_BATCH_SIZE };
    const key = batchId.toString();
    if (this.state.batchProofs.has(key)) return { ok: false, value: ERR_BATCH_ALREADY_PROCESSED };
    if (this.caller !== this.state.verifierPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    for (const proofId of proofIds) {
      const pKey = proofId.toString();
      const proof = this.state.proofs.get(pKey);
      if (!proof || !proof.isValid) return { ok: false, value: ERR_INVALID_PROOF };
    }
    this.state.batchProofs.set(key, {
      proofs: proofIds,
      processed: true,
      verifier: this.caller,
      timestamp: this.blockHeight,
    });
    return { ok: true, value: true };
  }

  revokeProof(proofId: Uint8Array): Result<boolean, number> {
    const key = proofId.toString();
    const proof = this.state.proofs.get(key);
    if (!proof) return { ok: false, value: ERR_PROOF_NOT_FOUND };
    if (this.caller !== proof.submitter && this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.proofs.set(key, { ...proof, isValid: false });
    return { ok: true, value: true };
  }

  updateProofExpiry(proofId: Uint8Array, newExpiry: number): Result<boolean, number> {
    const key = proofId.toString();
    const proof = this.state.proofs.get(key);
    if (!proof) return { ok: false, value: ERR_PROOF_NOT_FOUND };
    if (this.caller !== proof.submitter) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (newExpiry <= 0) return { ok: false, value: ERR_INVALID_EXPIRY };
    this.state.proofs.set(key, { ...proof, expiry: this.blockHeight + newExpiry });
    return { ok: true, value: true };
  }

  private arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((val, index) => val === b[index]);
  }
}

describe("ZKProofVerifier", () => {
  let contract: ZKProofVerifierMock;
  beforeEach(() => {
    contract = new ZKProofVerifierMock();
    contract.reset();
  });

  it("registers verification key successfully", () => {
    const keyId = new Uint8Array(32);
    const keyData = new Uint8Array(256);
    const result = contract.registerVerificationKey(keyId, keyData);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const key = contract.getVerificationKey(keyId).value as VerificationKey;
    expect(key.keyData).toEqual(keyData);
    expect(key.owner).toBe("ST1TEST");
  });

  it("submits proof successfully", () => {
    const proofId = new Uint8Array(32);
    const proofData = new Uint8Array(256).fill(1);
    const proofType = "snark";
    const category = "humane";
    const expiry = 100;
    const challenge = new Uint8Array(32).fill(2);
    const signature = new Uint8Array(64).fill(3);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    const result = contract.submitProof(proofId, proofData, proofType, category, expiry, challenge, signature, keyId);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const proof = contract.getProof(proofId).value as Proof;
    expect(proof.submitter).toBe("ST1TEST");
    expect(proof.isValid).toBe(true);
    expect(proof.proofType).toBe("snark");
    expect(proof.category).toBe("humane");
    expect(proof.expiry).toBe(100);
  });

  it("verifies proof successfully", () => {
    const proofId = new Uint8Array(32);
    const proofData = new Uint8Array(256).fill(1);
    const proofType = "snark";
    const category = "humane";
    const expiry = 100;
    const challenge = new Uint8Array(32).fill(2);
    const signature = new Uint8Array(64).fill(3);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId, proofData, proofType, category, expiry, challenge, signature, keyId);
    const result = contract.verifyProof(proofId, challenge);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("submits batch proofs successfully", () => {
    const batchId = new Uint8Array(32);
    const proofId1 = new Uint8Array(32).fill(1);
    const proofId2 = new Uint8Array(32).fill(2);
    const proofIds = [proofId1, proofId2];
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId1, new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32), new Uint8Array(64), keyId);
    contract.submitProof(proofId2, new Uint8Array(256), "stark", "feed", 100, new Uint8Array(32), new Uint8Array(64), keyId);
    contract.caller = "ST1TEST";
    const result = contract.submitBatchProofs(batchId, proofIds, keyId);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const batch = contract.getBatch(batchId).value as BatchProof;
    expect(batch.processed).toBe(true);
    expect(batch.verifier).toBe("ST1TEST");
  });

  it("revokes proof successfully", () => {
    const proofId = new Uint8Array(32);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId, new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32), new Uint8Array(64), keyId);
    const result = contract.revokeProof(proofId);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const proof = contract.getProof(proofId).value as Proof;
    expect(proof.isValid).toBe(false);
  });

  it("updates proof expiry successfully", () => {
    const proofId = new Uint8Array(32);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId, new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32), new Uint8Array(64), keyId);
    const result = contract.updateProofExpiry(proofId, 200);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const proof = contract.getProof(proofId).value as Proof;
    expect(proof.expiry).toBe(200);
  });

  it("rejects submit proof when system paused", () => {
    contract.pauseSystem(true);
    const result = contract.submitProof(new Uint8Array(32), new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32), new Uint8Array(64), new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_SYSTEM_PAUSED);
  });

  it("rejects verify proof with expired proof", () => {
    const proofId = new Uint8Array(32);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId, new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32), new Uint8Array(64), keyId);
    contract.blockHeight = 101;
    const result = contract.verifyProof(proofId, new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_PROOF_EXPIRED);
  });

  it("rejects submit proof with invalid type", () => {
    const result = contract.submitProof(new Uint8Array(32), new Uint8Array(256), "invalid", "humane", 100, new Uint8Array(32), new Uint8Array(64), new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_PROOF_TYPE);
  });

  it("rejects register key with empty data", () => {
    const result = contract.registerVerificationKey(new Uint8Array(32), new Uint8Array(0));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_VERIFICATION_KEY);
  });

  it("parses proof type with Clarity", () => {
    const cv = stringAsciiCV("snark");
    expect(cv.value).toBe("snark");
  });

  it("parses expiry with Clarity", () => {
    const cv = uintCV(100);
    expect(cv.value).toEqual(BigInt(100));
  });

  it("rejects batch with invalid size", () => {
    const result = contract.submitBatchProofs(new Uint8Array(32), [], new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_BATCH_SIZE);
  });

  it("rejects revoke by unauthorized", () => {
    const proofId = new Uint8Array(32);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId, new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32), new Uint8Array(64), keyId);
    contract.caller = "ST2FAKE";
    const result = contract.revokeProof(proofId);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("rejects update expiry by unauthorized", () => {
    const proofId = new Uint8Array(32);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId, new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32), new Uint8Array(64), keyId);
    contract.caller = "ST2FAKE";
    const result = contract.updateProofExpiry(proofId, 200);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("sets max proofs successfully", () => {
    const result = contract.setMaxProofs(5000);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.maxProofs).toBe(5000);
  });

  it("sets default expiry successfully", () => {
    const result = contract.setDefaultExpiry(200);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.defaultExpiry).toBe(200);
  });

  it("rejects verify proof with mismatch challenge", () => {
    const proofId = new Uint8Array(32);
    const keyId = new Uint8Array(32);
    contract.registerVerificationKey(keyId, new Uint8Array(256));
    contract.submitProof(proofId, new Uint8Array(256), "snark", "humane", 100, new Uint8Array(32).fill(1), new Uint8Array(64), keyId);
    const result = contract.verifyProof(proofId, new Uint8Array(32).fill(2));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_CHALLENGE_MISMATCH);
  });

  it("rejects batch by non-verifier", () => {
    contract.caller = "ST2FAKE";
    const result = contract.submitBatchProofs(new Uint8Array(32), [new Uint8Array(32)], new Uint8Array(32));
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });
});