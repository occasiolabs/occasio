'use strict';

/**
 * Audit-layer error classes.
 *
 * AuditWriteError signals that the auditor could not append a row to its
 * sink. v0.6.4 treats this as session-fatal — see src/index.js's request
 * handler for the abort behaviour. The dropped row is attached so a
 * supervisor / log scraper can recover it from stderr if needed.
 */

class AuditWriteError extends Error {
  constructor(cause, droppedRow) {
    super(`audit write failed: ${cause && cause.message ? cause.message : cause}`);
    this.name        = 'AuditWriteError';
    this.cause       = cause;
    this.droppedRow  = droppedRow;
  }
}

module.exports = { AuditWriteError };
