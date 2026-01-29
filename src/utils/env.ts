/**
 * Environment Variable Utilities
 *
 * Provides type-safe access to required environment variables
 * with clear error messages for missing values.
 *
 * @module utils/env
 * @version 1.0.0
 */

/**
 * Error thrown when a required environment variable is missing.
 */
export class MissingEnvironmentVariableError extends Error {
  constructor(
    public readonly variableName: string,
    public readonly description?: string
  ) {
    const message = description
      ? `Required environment variable ${variableName} is not set: ${description}`
      : `Required environment variable ${variableName} is not set`;
    super(message);
    this.name = 'MissingEnvironmentVariableError';
  }
}

/**
 * Get a required environment variable.
 *
 * @param name - Environment variable name
 * @param description - Optional description for error messages
 * @returns The environment variable value
 * @throws MissingEnvironmentVariableError if not set
 *
 * @example
 * ```typescript
 * const password = getRequiredEnv('XRPL_WALLET_PASSWORD', 'Master encryption password');
 * ```
 */
export function getRequiredEnv(name: string, description?: string): string {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new MissingEnvironmentVariableError(name, description);
  }
  return value;
}

/**
 * Get an optional environment variable with a default value.
 *
 * @param name - Environment variable name
 * @param defaultValue - Default value if not set
 * @returns The environment variable value or default
 *
 * @example
 * ```typescript
 * const network = getOptionalEnv('XRPL_NETWORK', 'testnet');
 * ```
 */
export function getOptionalEnv(name: string, defaultValue: string): string {
  const value = process.env[name];
  return value !== undefined && value !== '' ? value : defaultValue;
}

/**
 * Get the wallet password from environment.
 *
 * This is a convenience function that provides a clear error message
 * specific to the wallet password requirement.
 *
 * @returns The wallet password
 * @throws MissingEnvironmentVariableError if not set
 */
export function getWalletPassword(): string {
  return getRequiredEnv(
    'XRPL_WALLET_PASSWORD',
    'Master encryption password for wallet keystore. Set this environment variable to a strong password.'
  );
}

/**
 * Validate required environment variables at startup.
 *
 * Call this function early in the application lifecycle to fail fast
 * if required configuration is missing.
 *
 * @param variables - Array of [name, description] tuples
 * @throws MissingEnvironmentVariableError for the first missing variable
 *
 * @example
 * ```typescript
 * validateRequiredEnv([
 *   ['XRPL_WALLET_PASSWORD', 'Master encryption password'],
 *   ['XRPL_NETWORK', 'Target XRPL network'],
 * ]);
 * ```
 */
export function validateRequiredEnv(variables: [string, string?][]): void {
  for (const [name, description] of variables) {
    getRequiredEnv(name, description);
  }
}
