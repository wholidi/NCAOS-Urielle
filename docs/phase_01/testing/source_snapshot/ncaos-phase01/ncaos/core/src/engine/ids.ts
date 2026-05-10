/**
 * @ncaos/core — ID & Reference Generation
 *
 * Generates typed identifiers used throughout the EGS:
 * - RequestId (REQ-XXXXXX)
 * - EvidenceHandle (EVD-{timestamp}-{hash})
 *
 * These are structural references only — they do not contain
 * or imply knowledge of internal system state.
 */

import type { EvidenceHandle, RequestId } from '../types/contracts.js';

let _reqCounter = 0;

/**
 * Generates a sequential RequestId.
 * Format: REQ-XXXXXX (zero-padded 6 digits, grows beyond 6 for high volume)
 *
 * In production, seed _reqCounter from the last persisted event sequence number
 * to ensure continuity across restarts.
 */
export function generateRequestId(seed?: number): RequestId {
  if (seed !== undefined) _reqCounter = seed;
  _reqCounter++;
  return `REQ-${String(_reqCounter).padStart(6, '0')}` as RequestId;
}

/**
 * Generates an EvidenceHandle for a containment event.
 * Format: EVD-{unix-ms}-{hex-hash}
 *
 * The hash is derived from the requestId + detectedAt timestamp,
 * providing a short stable reference for audit retrieval.
 * Not cryptographically secure — use signed log entries for tamper-evidence.
 */
export function generateEvidenceHandle(
  requestId: string,
  detectedAt: string,
): EvidenceHandle {
  const ts = new Date(detectedAt).getTime();
  const hashInput = `${requestId}::${ts}`;
  const hash = simpleHash(hashInput).toString(16).toUpperCase().padStart(8, '0');
  return `EVD-${ts}-${hash}` as EvidenceHandle;
}

/**
 * Simple deterministic hash for evidence handle generation.
 * Not cryptographic — use HMAC for production tamper-evidence.
 */
function simpleHash(str: string): number {
  let hash = 0x811c9dc5; // FNV offset basis
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0; // FNV prime, unsigned 32-bit
  }
  return hash;
}

/**
 * Returns the current timestamp as an ISO 8601 string.
 * Used for detectedAt and enforcedAt fields.
 */
export function nowIso(): string {
  return new Date().toISOString();
}
