# Tenant365 Modules: Microsoft Authentication

Lightweight, dependency-minimal package for authenticating against Microsoft 365 / Azure AD using the OAuth 2.0 **client credentials** flow. Supports three signing strategies:

- **Client Secret** — simplest setup
- **Certificate (local private key)** — private key stored on the server
- **Certificate (Azure Key Vault signing)** — private key never leaves Key Vault

---

## Installation

```bash
npm install @tenant365/msauth
# or
pnpm add @tenant365/msauth
```

---

## Quick Start

### 1. Client Secret

```typescript
import { createM365ClientCredentials } from "@tenant365/msauth";

const auth = createM365ClientCredentials({
  tenantId: "YOUR_TENANT_ID",
  clientId: "YOUR_CLIENT_ID",
  clientSecret: "YOUR_CLIENT_SECRET",
});

// Get a token for Microsoft Graph (default scope)
const { token, expiresAt } = await auth.GetAccessToken();

// Get a token for a specific scope
const { token: kvToken } = await auth.GetAccessToken("https://vault.azure.net/.default");
```

### 2. Certificate with local private key

```typescript
import { createM365ClientCertificate } from "@tenant365/msauth";
import { readFileSync } from "fs";

const auth = createM365ClientCertificate({
  tenantId: "YOUR_TENANT_ID",
  clientId: "YOUR_CLIENT_ID",
  privateKey: readFileSync("./private.key", "utf-8"), // PEM string or CryptoKey
  certificate: readFileSync("./public.crt", "utf-8"), // PEM string — used for x5t thumbprint
});

const { token, expiresAt } = await auth.GetAccessToken();
```

### 3. Certificate + Azure Key Vault signing (key never leaves Key Vault)

```typescript
import { getM365AccessTokenWithKeyVaultSigning } from "@tenant365/msauth";

const { token, expiresAt } = await getM365AccessTokenWithKeyVaultSigning({
  tenantId: "YOUR_TENANT_ID",
  clientId: "YOUR_CLIENT_ID",
  clientSecret: "YOUR_CLIENT_SECRET", // used only to authenticate against Key Vault
  keyVaultName: "my-keyvault",
  certificateName: "my-certificate",
  keyName: "my-key",
  // Optional: override Key Vault credentials if different from target tenant
  // keyVaultTenantId: "...",
  // keyVaultClientId: "...",
  // keyVaultClientSecret: "...",
  // certificateVersion: "abc123",
  // keyVersion: "def456",
  // scope: "https://graph.microsoft.com/.default",
});
```

---

## API Reference

### Functions

#### `createM365ClientCredentials(credentials)`

Creates an authentication object for the **client secret** flow.

| Parameter | Type | Description |
|---|---|---|
| `tenantId` | `string` | Azure AD tenant ID |
| `clientId` | `string` | App registration client ID |
| `clientSecret` | `string` | App registration client secret |

Returns `M365ClientCredentials` with a `GetAccessToken(scope?)` method.

---

#### `createM365ClientCertificate(credentials)`

Creates an authentication object for the **certificate** flow, signing locally.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tenantId` | `string` | yes | Azure AD tenant ID |
| `clientId` | `string` | yes | App registration client ID |
| `privateKey` | `string \| CryptoKey` | yes* | PKCS#8 PEM string or Web Crypto `CryptoKey` |
| `certificate` | `string` | yes* | Public certificate PEM — used to compute `x5t`/`x5t#S256` header |
| `keyId` | `string` | no | Custom `kid` header value (alternative to certificate thumbprints) |
| `keyVaultSigner` | `M365KeyVaultJwtSigner` | no | External signing backend (see below) |

\* Either `certificate` (for thumbprint-based identification) or `keyId` must be provided. Either `privateKey` or `keyVaultSigner` must be provided for signing.

Returns `M365ClientCertificate` with a `GetAccessToken(scope?)` method.

---

#### `getM365AccessToken(credentials, scope?)`

Low-level function — fetches a token directly without creating a persistent auth object.

| Parameter | Type | Default |
|---|---|---|
| `credentials` | `MS365ClientCredentials` | — |
| `scope` | `string` | `https://graph.microsoft.com/.default` |

Returns `Promise<M365AccessToken>`.

---

#### `getM365AccessTokenWithNodeSigning(request)`

Convenience function — combines `createM365ClientCertificate` + `GetAccessToken` in one call for local key signing.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tenantId` | `string` | yes | Azure AD tenant ID |
| `clientId` | `string` | yes | App registration client ID |
| `privateKey` | `string \| CryptoKey` | yes | PKCS#8 PEM or `CryptoKey` |
| `certificate` | `string` | yes | Public certificate PEM |
| `scope` | `string` | no | Defaults to Graph scope |

Returns `Promise<M365AccessToken>`.

---

#### `getM365AccessTokenWithKeyVaultSigning(request)`

Convenience function — fetches the certificate from Key Vault, signs the JWT assertion using Key Vault, and returns a token for the target tenant.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tenantId` | `string` | yes | Target Azure AD tenant ID |
| `clientId` | `string` | yes | App registration client ID |
| `clientSecret` | `string` | yes | Secret used to authenticate against Key Vault |
| `keyVaultName` | `string` | yes | Key Vault name (without `.vault.azure.net`) |
| `certificateName` | `string` | yes | Certificate name in Key Vault |
| `keyName` | `string` | yes | Key name in Key Vault |
| `scope` | `string` | no | Defaults to Graph scope |
| `keyVaultTenantId` | `string` | no | Override tenant for Key Vault auth |
| `keyVaultClientId` | `string` | no | Override client ID for Key Vault auth |
| `keyVaultClientSecret` | `string` | no | Override client secret for Key Vault auth |
| `certificateVersion` | `string` | no | Pin to a specific certificate version |
| `keyVersion` | `string` | no | Pin to a specific key version |

Returns `Promise<M365AccessToken>`.

---

#### `getM365KeyVaultCertificate(request)`

Fetches a certificate from Azure Key Vault.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `vaultName` | `string` | yes | Key Vault name |
| `certificateName` | `string` | yes | Certificate name |
| `certificateVersion` | `string` | no | Specific version; latest if omitted |
| `authentication` | `M365Authentication` | yes | Auth object from `createM365Client*` |

Returns `Promise<M365KeyVaultCertificate>`:

```typescript
{
  id: string;          // Full Key Vault resource ID
  name: string;        // Certificate name
  version: string;     // Resolved version
  x509DerBase64: string; // DER-encoded certificate (Base64)
  x509Pem: string;     // PEM-encoded certificate
}
```

---

#### `getM365KeyVaultSecret(request)`

Fetches a secret from Azure Key Vault.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `vaultName` | `string` | yes | Key Vault name |
| `secretName` | `string` | yes | Secret name |
| `secretVersion` | `string` | no | Specific version; latest if omitted |
| `authentication` | `M365Authentication` | yes | Auth object |

Returns `Promise<M365KeyVaultSecret>`:

```typescript
{
  id: string;
  name: string;
  version: string;
  value: string;
}
```

---

#### `createM365KeyVaultJwtSigner(request)`

Creates a signer object that delegates JWT signing to Azure Key Vault. Pass this to `createM365ClientCertificate` as `keyVaultSigner` for advanced scenarios.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `vaultName` | `string` | yes | Key Vault name |
| `keyName` | `string` | yes | Key name |
| `keyVersion` | `string` | no | Specific key version |
| `authentication` | `M365Authentication` | yes | Auth object with Key Vault access |

Returns `M365KeyVaultJwtSigner`:

```typescript
{
  keyId: string;  // Full Key Vault key URI (used as `kid` in JWT header)
  sign: (signingInput: string, alg: string) => Promise<string>;
}
```

---

### Types

```typescript
type M365AccessToken = {
  token: string;     // Bearer token
  expiresAt: Date;   // Expiry time
};

type M365Authentication = M365ClientCredentials | M365ClientCertificate;
```

---

### Predefined Scopes

```typescript
import { MS365Scopes } from "@tenant365/msauth";

MS365Scopes.DEFAULT    // "https://graph.microsoft.com/.default"
MS365Scopes.KEY_VAULT  // "https://vault.azure.net/.default"
```

---

## Debug Mode

Set the environment variable `TENANT365_MS_AUTH_DEBUG=1` to log the JWT assertion header to the console. Do not enable in production.

```bash
TENANT365_MS_AUTH_DEBUG=1 node your-app.js
```

---

## Requirements

- Node.js 18+ or a runtime with the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (`globalThis.crypto`)
- The consuming project's TypeScript config should use `moduleResolution: "bundler"`, `"node16"`, or `"nodenext"` to resolve the `exports` field correctly

---

## License

MIT — [Tenant365](https://tenant365.cloud)
