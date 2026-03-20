import { SignJWT, importPKCS8 } from "jose";
import { MS365Scopes } from "./scopes";

export interface MS365ClientCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface MS365CertificateCredentials {
  tenantId: string;
  clientId: string;
  privateKey?: CryptoKey | string;
  certificate?: string;
  keyId?: string;
  keyVaultSigner?: {
    keyId?: string;
    sign: (signingInput: string, alg: string) => Promise<string>;
  };
}

export type M365AccessToken = {
  token: string;
  expiresAt: Date;
};

export interface M365AuthenticationMethod {
  GetAccessToken: (scope?: string) => Promise<M365AccessToken>;
}

export interface M365ClientCredentials
  extends MS365ClientCredentials, M365AuthenticationMethod {}

export interface M365ClientCertificate
  extends MS365CertificateCredentials, M365AuthenticationMethod {}

export type M365Authentication = M365ClientCredentials | M365ClientCertificate;

const base64UrlEncodeBytes = (bytes: Uint8Array): string => {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  let base64 = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b1 = bytes[i];
    const b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;

    const chunk = (b1 << 16) | (b2 << 8) | b3;

    const hasB2 = i + 1 < bytes.length;
    const hasB3 = i + 2 < bytes.length;

    base64 += alphabet[(chunk >> 18) & 63];
    base64 += alphabet[(chunk >> 12) & 63];
    base64 += hasB2 ? alphabet[(chunk >> 6) & 63] : "=";
    base64 += hasB3 ? alphabet[chunk & 63] : "=";
  }

  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

const pemCertificateToDerBytes = (pem: string): Uint8Array => {
  const cleaned = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");

  if (typeof atob !== "function") {
    throw new Error("Base64 decoder 'atob' is not available in this runtime.");
  }

  const binary = atob(cleaned);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
};

const getCertificateThumbprints = async (certificatePem: string) => {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj)
    throw new Error("WebCrypto API (globalThis.crypto) is not available.");

  const derBytes = pemCertificateToDerBytes(certificatePem);
  const derArrayBuffer = derBytes.buffer.slice(
    derBytes.byteOffset,
    derBytes.byteOffset + derBytes.byteLength,
  ) as ArrayBuffer;
  const sha1 = await cryptoObj.subtle.digest("SHA-1", derArrayBuffer);
  const sha256 = await cryptoObj.subtle.digest("SHA-256", derArrayBuffer);

  return {
    x5t: base64UrlEncodeBytes(new Uint8Array(sha1)),
    "x5t#S256": base64UrlEncodeBytes(new Uint8Array(sha256)),
  };
};

const getJwtAlgFromPrivateKey = (
  privateKey: CryptoKey | string,
): { alg: string } => {
  if (typeof privateKey === "string") return { alg: "RS256" };

  const keyAlg: any = privateKey.algorithm;
  const hashName: string | undefined = keyAlg?.hash?.name;
  switch (hashName) {
    case "SHA-256":
      return { alg: "RS256" };
    case "SHA-384":
      return { alg: "RS384" };
    case "SHA-512":
      return { alg: "RS512" };
    default:
      return { alg: "RS256" };
  }
};

const getM365ClientCertificateClientAssertion = async (
  credentials: MS365CertificateCredentials,
): Promise<string> => {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj)
    throw new Error("WebCrypto API (globalThis.crypto) is not available.");

  const { alg } = credentials.privateKey
    ? getJwtAlgFromPrivateKey(credentials.privateKey)
    : { alg: "RS256" };

  const now = Math.floor(Date.now() / 1000);
  const iat = now;
  const nbf = now - 60;
  const exp = iat + 600;

  const jti =
    typeof cryptoObj.randomUUID === "function"
      ? cryptoObj.randomUUID()
      : `${iat}-${Math.random().toString(16).slice(2)}`;

  const tokenEndpoint = `https://login.microsoftonline.com/${credentials.tenantId}/oauth2/v2.0/token`;

  const thumbprints = credentials.certificate
    ? await getCertificateThumbprints(credentials.certificate)
    : {};

  const protectedHeader: Record<string, unknown> = {
    alg,
    typ: "JWT",
    ...thumbprints,
  };

  if (credentials.keyId ?? credentials.keyVaultSigner?.keyId) {
    protectedHeader.kid = credentials.keyId ?? credentials.keyVaultSigner?.keyId;
  }

  if (
    !("x5t" in protectedHeader) &&
    !("x5t#S256" in protectedHeader) &&
    !(credentials.keyId ?? credentials.keyVaultSigner?.keyId)
  ) {
    throw new Error(
      "Missing certificate thumbprint identifiers for M365 client assertion. Provide `certificate` (PEM) for x5t/x5t#S256 or set `keyId` for `kid`.",
    );
  }

  if (
    typeof process !== "undefined" &&
    process.env &&
    process.env.TENANT365_MS_AUTH_DEBUG === "1"
  ) {
    console.log("M365 client assertion header", protectedHeader);
  }

  if (credentials.privateKey) {
    const key =
      typeof credentials.privateKey === "string"
        ? await importPKCS8(credentials.privateKey, alg)
        : credentials.privateKey;

    return await new SignJWT({})
      .setProtectedHeader(protectedHeader as any)
      .setIssuer(credentials.clientId)
      .setSubject(credentials.clientId)
      .setAudience(tokenEndpoint)
      .setJti(jti)
      .setIssuedAt(iat)
      .setNotBefore(nbf)
      .setExpirationTime(exp)
      .sign(key);
  }

  if (!credentials.keyVaultSigner) {
    throw new Error(
      "Missing signing configuration. Provide `privateKey` or `keyVaultSigner`.",
    );
  }

  const payload = {
    iss: credentials.clientId,
    sub: credentials.clientId,
    aud: tokenEndpoint,
    jti,
    iat,
    nbf,
    exp,
  };

  const encoder = new TextEncoder();
  const encodedHeader = base64UrlEncodeBytes(
    encoder.encode(JSON.stringify(protectedHeader)),
  );
  const encodedPayload = base64UrlEncodeBytes(
    encoder.encode(JSON.stringify(payload)),
  );
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await credentials.keyVaultSigner.sign(signingInput, alg);
  return `${signingInput}.${signature}`;
};

const getM365AccessTokenFromClientCertificate = async (
  credentials: MS365CertificateCredentials,
  scope: string = MS365Scopes.DEFAULT,
): Promise<M365AccessToken> => {
  const clientAssertion =
    await getM365ClientCertificateClientAssertion(credentials);

  const response = await fetch(
    `https://login.microsoftonline.com/${credentials.tenantId}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: credentials.clientId,
        scope,
        client_assertion_type:
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        client_assertion: clientAssertion,
      }),
    },
  );

  const data = await response.json().catch(async () => {
    const text = await response.text().catch(() => "");
    return { raw: text };
  });

  if (!response.ok) {
    throw new Error(
      `M365 token request failed: ${response.status} ${response.statusText} - ${JSON.stringify(data)}`,
    );
  }

  return {
    token: data.access_token,
    expiresAt: new Date(Date.now() + data.expires_in * 1000),
  };
};

export const getM365AccessToken = async (
  credentials: MS365ClientCredentials,
  scope: string = MS365Scopes.DEFAULT,
): Promise<M365AccessToken> => {
  const response = await fetch(
    `https://login.microsoftonline.com/${credentials.tenantId}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: credentials.clientId,
        client_secret: credentials.clientSecret,
        scope,
      }),
    },
  );

  const data = await response.json().catch(async () => {
    const text = await response.text().catch(() => "");
    return { raw: text };
  });

  if (!response.ok) {
    throw new Error(
      `M365 token request failed: ${response.status} ${response.statusText} - ${JSON.stringify(data)}`,
    );
  }

  return {
    token: data.access_token,
    expiresAt: new Date(Date.now() + data.expires_in * 1000),
  };
};

export const createM365ClientCredentials = (
  credentials: MS365ClientCredentials,
): M365ClientCredentials => ({
  ...credentials,
  GetAccessToken: (scope?: string) =>
    getM365AccessToken(credentials, scope ?? MS365Scopes.DEFAULT),
});

export const createM365ClientCertificate = (
  credentials: MS365CertificateCredentials,
): M365ClientCertificate => ({
  ...credentials,
  GetAccessToken: (scope?: string) =>
    getM365AccessTokenFromClientCertificate(
      credentials,
      scope ?? MS365Scopes.DEFAULT,
    ),
});
