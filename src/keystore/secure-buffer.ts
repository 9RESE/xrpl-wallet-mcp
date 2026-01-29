/**
 * SecureBuffer - Memory-safe container for sensitive cryptographic data.
 *
 * This class provides controlled access to sensitive data (private keys, seeds)
 * with automatic memory zeroing and serialization prevention.
 *
 * Security Features:
 * - Automatic zeroing of source buffer on creation
 * - Explicit disposal with multiple overwrite passes
 * - Prevention of accidental serialization (JSON, toString)
 * - Clear lifecycle tracking
 *
 * @module keystore/secure-buffer
 * @version 1.0.0
 */

/**
 * SecureBuffer provides memory-safe handling of sensitive data.
 *
 * USAGE:
 * ```typescript
 * const secure = SecureBuffer.from(sensitiveData);
 * try {
 *   // Use secure.getBuffer() for operations
 *   const result = someOperation(secure.getBuffer());
 * } finally {
 *   secure.dispose(); // Always dispose when done
 * }
 * ```
 *
 * SECURITY NOTES:
 * - Source buffer is zeroed when creating from existing data
 * - Buffer contents are overwritten with multiple passes on dispose
 * - Serialization methods throw to prevent accidental exposure
 */
export class SecureBuffer {
  private buffer: Buffer;
  private isDisposed: boolean = false;

  /**
   * Private constructor - use static factory methods.
   */
  private constructor(size: number) {
    // Use allocUnsafe for performance since we'll fill it immediately
    this.buffer = Buffer.allocUnsafe(size);
  }

  /**
   * Creates a new SecureBuffer with uninitialized content of specified size.
   *
   * @param size - Size in bytes
   * @returns New SecureBuffer instance
   */
  static alloc(size: number): SecureBuffer {
    if (size <= 0) {
      throw new Error('SecureBuffer size must be positive');
    }
    const secure = new SecureBuffer(size);
    // Fill with zeros for safety
    secure.buffer.fill(0);
    return secure;
  }

  /**
   * Creates a SecureBuffer from existing data.
   *
   * IMPORTANT: The source buffer is zeroed immediately after copying
   * to prevent the original data from remaining in memory.
   *
   * @param data - Source buffer (will be zeroed)
   * @param verify - If true, verify source was zeroed (default: false for performance)
   * @returns New SecureBuffer containing the copied data
   */
  static from(data: Buffer, verify: boolean = false): SecureBuffer {
    if (!Buffer.isBuffer(data)) {
      throw new Error('SecureBuffer.from requires a Buffer');
    }
    if (data.length === 0) {
      throw new Error('SecureBuffer cannot be empty');
    }

    const secure = new SecureBuffer(data.length);
    // Copy data to secure buffer
    data.copy(secure.buffer);
    // Zero the source buffer immediately
    data.fill(0);

    // Optionally verify the source was zeroed
    if (verify) {
      const zeroBuffer = Buffer.alloc(data.length, 0);
      if (!data.equals(zeroBuffer)) {
        // This should not happen - indicates a serious issue
        throw new Error('SecureBuffer: Source buffer zeroing verification failed');
      }
    }

    return secure;
  }

  /**
   * Gets the buffer contents for use in cryptographic operations.
   *
   * @returns The internal Buffer
   * @throws Error if buffer has been disposed
   */
  getBuffer(): Buffer {
    if (this.isDisposed) {
      throw new Error('SecureBuffer has been disposed');
    }
    return this.buffer;
  }

  /**
   * Disposes the buffer by securely zeroing its contents.
   *
   * This operation is irreversible. Multiple overwrite passes are used
   * to help prevent data recovery.
   */
  dispose(): void {
    if (!this.isDisposed) {
      // Multiple overwrite passes for secure deletion
      // Pass 1: Zeros
      this.buffer.fill(0x00);
      // Pass 2: Ones
      this.buffer.fill(0xff);
      // Pass 3: Zeros again
      this.buffer.fill(0x00);

      this.isDisposed = true;
    }
  }

  /**
   * Alias for dispose() - matches common naming conventions.
   */
  zero(): void {
    this.dispose();
  }

  /**
   * Returns whether the buffer has been disposed.
   */
  get disposed(): boolean {
    return this.isDisposed;
  }

  /**
   * Alias for disposed getter - matches spec naming.
   */
  get zeroed(): boolean {
    return this.isDisposed;
  }

  /**
   * Buffer length in bytes.
   */
  get length(): number {
    return this.buffer.length;
  }

  /**
   * Executes an operation with the buffer and ensures cleanup on completion.
   *
   * The SecureBuffer is automatically disposed after the operation,
   * regardless of success or failure.
   *
   * @param secure - SecureBuffer to use
   * @param operation - Async operation that uses the buffer
   * @returns Result of the operation
   */
  static async withSecure<T>(
    secure: SecureBuffer,
    operation: (buffer: Buffer) => Promise<T>
  ): Promise<T> {
    try {
      return await operation(secure.getBuffer());
    } finally {
      secure.dispose();
    }
  }

  /**
   * Creates a SecureBuffer, executes an operation, and disposes it.
   *
   * @param data - Source buffer (will be zeroed)
   * @param operation - Async operation that uses the buffer
   * @returns Result of the operation
   */
  static async withSecureBuffer<T>(
    data: Buffer,
    operation: (buffer: Buffer) => Promise<T>
  ): Promise<T> {
    const secure = SecureBuffer.from(data);
    try {
      return await operation(secure.getBuffer());
    } finally {
      secure.dispose();
    }
  }

  // ========================================================================
  // Serialization Prevention
  // ========================================================================

  /**
   * Prevents JSON serialization of sensitive data.
   * @throws Error always
   */
  toJSON(): never {
    throw new Error('SecureBuffer cannot be serialized to JSON');
  }

  /**
   * Returns a placeholder string instead of buffer contents.
   */
  toString(): string {
    return '[SecureBuffer]';
  }

  /**
   * Custom Node.js inspection - prevents accidental logging of contents.
   */
  [Symbol.for('nodejs.util.inspect.custom')](): string {
    return `[SecureBuffer length=${this.length} disposed=${this.isDisposed}]`;
  }

  /**
   * Prevents spreading/iteration of buffer contents.
   */
  [Symbol.iterator](): never {
    throw new Error('SecureBuffer cannot be iterated');
  }
}
