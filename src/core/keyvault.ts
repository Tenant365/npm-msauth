import { MS365Scopes } from "./scopes";
import type { M365Authentication } from "./auth";

export interface M365KeyVaultCertificateRequest {
  vaultName: string;
  certificateName: string;
  certificateVersion?: string;
  authentication: M365Authentication;
}

export interface M365KeyVaultCertificate {
  id: string;
  name: string;
  version: string;
  x509DerBase64: string;
  x509Pem: string;
}

export interface M365KeyVaultSecretRequest {
  vaultName: string;
  secretName: string;
  secretVersion?: string;
  authentication: M365Authentication;
}

export interface M365KeyVaultSecret {
  id: string;
  name: string;
  version: string;
  value: string;
}

export interface M365KeyVaultJwtSignerRequest {
  vaultName: string;
  keyName: string;
  keyVersion?: string;
  authentication: M365Authentication;
}

export interface M365KeyVaultJwtSigner {
  keyId: string;
  sign: (signingInput: string, alg: string) => Promise<string>;
}

type KeyVaultCertificateApiResponse = {
  id: string;
  x5c?: string[];
  cer?: string;
};

type KeyVaultSecretApiResponse = {
  id: string;
  value?: string;
};

type KeyVaultSignApiResponse = {
  kid?: string;
  value?: string;
};

const normalizeBase64 = (value: string): string =>
  value.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");

const base64ToPem = (base64Value: string): string => {
  const normalized = normalizeBase64(base64Value);
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const lines = padded.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
};

const base64UrlEncode = (value: Uint8Array): string => {
  const base64 = btoa(String.fromCharCode(...value));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const utf8ToBytes = (value: string): Uint8Array =>
  new TextEncoder().encode(value);

export const getM365KeyVaultCertificate = async (
  request: M365KeyVaultCertificateRequest,
): Promise<M365KeyVaultCertificate> => {
  const versionPath = request.certificateVersion
    ? `/${request.certificateVersion}`
    : "";
  const url = `https://${request.vaultName}.vault.azure.net/certificates/${request.certificateName}${versionPath}?api-version=7.5`;

  const token = await request.authentication.GetAccessToken(
    MS365Scopes.KEY_VAULT,
  );
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token.token}`,
      "Content-Type": "application/json",
    },
  });

  const data = (await response.json().catch(async () => {
    const text = await response.text().catch(() => "");
    return { raw: text };
  })) as KeyVaultCertificateApiResponse & Record<string, unknown>;

  if (!response.ok) {
    throw new Error(
      `Key Vault certificate request failed: ${response.status} ${response.statusText} - ${JSON.stringify(data)}`,
    );
  }

  // Key Vault may return certificate bytes as `cer` (common) or as `x5c[0]`.
  const rawCertificate = data.x5c?.[0] ?? data.cer;
  if (!rawCertificate) {
    throw new Error(
      "Key Vault response does not contain certificate data (x5c or cer).",
    );
  }

  const idParts = (data.id ?? "").split("/");
  const version = idParts[idParts.length - 1] ?? "";

  return {
    id: data.id ?? "",
    name: request.certificateName,
    version,
    x509DerBase64: rawCertificate,
    x509Pem: base64ToPem(rawCertificate),
  };
};

export const getM365KeyVaultSecret = async (
  request: M365KeyVaultSecretRequest,
): Promise<M365KeyVaultSecret> => {
  const versionPath = request.secretVersion ? `/${request.secretVersion}` : "";
  const url = `https://${request.vaultName}.vault.azure.net/secrets/${request.secretName}${versionPath}?api-version=7.5`;

  const token = await request.authentication.GetAccessToken(
    MS365Scopes.KEY_VAULT,
  );
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token.token}`,
      "Content-Type": "application/json",
    },
  });

  const data = (await response.json().catch(async () => {
    const text = await response.text().catch(() => "");
    return { raw: text };
  })) as KeyVaultSecretApiResponse & Record<string, unknown>;

  if (!response.ok) {
    throw new Error(
      `Key Vault secret request failed: ${response.status} ${response.statusText} - ${JSON.stringify(data)}`,
    );
  }

  if (!data.value) {
    throw new Error("Key Vault response does not contain secret value.");
  }

  const idParts = (data.id ?? "").split("/");
  const version = idParts[idParts.length - 1] ?? "";

  return {
    id: data.id ?? "",
    name: request.secretName,
    version,
    value: data.value,
  };
};

export const createM365KeyVaultJwtSigner = (
  request: M365KeyVaultJwtSignerRequest,
): M365KeyVaultJwtSigner => {
  const versionPath = request.keyVersion ? `/${request.keyVersion}` : "";
  const keyPath = `${request.vaultName}.vault.azure.net/keys/${request.keyName}${versionPath}`;
  const keyId = `https://${keyPath}`;

  return {
    keyId,
    sign: async (signingInput: string, alg: string): Promise<string> => {
      const cryptoObj = globalThis.crypto;
      if (!cryptoObj)
        throw new Error("WebCrypto API (globalThis.crypto) is not available.");

      const digestAlgorithm =
        alg === "RS512" ? "SHA-512" : alg === "RS384" ? "SHA-384" : "SHA-256";

      const digest = await cryptoObj.subtle.digest(
        digestAlgorithm,
        utf8ToBytes(signingInput).buffer as ArrayBuffer,
      );
      const digestValue = base64UrlEncode(new Uint8Array(digest));

      const token = await request.authentication.GetAccessToken(
        MS365Scopes.KEY_VAULT,
      );
      const response = await fetch(`https://${keyPath}/sign?api-version=7.5`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          alg,
          value: digestValue,
        }),
      });

      const data = (await response.json().catch(async () => {
        const text = await response.text().catch(() => "");
        return { raw: text };
      })) as KeyVaultSignApiResponse & Record<string, unknown>;

      if (!response.ok) {
        throw new Error(
          `Key Vault sign request failed: ${response.status} ${response.statusText} - ${JSON.stringify(data)}`,
        );
      }

      if (!data.value) {
        throw new Error(
          "Key Vault sign response does not contain signature value.",
        );
      }

      return data.value;
    },
  };
};
