import { SignJWT } from "jose";
import { MS365Scopes } from "./scopes";

export interface MS365ClientCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface MS365CertificateCredentials {
  tenantId: string;
  clientId: string;
  privateKey: CryptoKey;
}

export type M365AccessToken = {
  token: string;
  expiresAt: Date;
};

export interface M365AuthenticationMethod {
  GetAccessToken: (scope?: string) => Promise<M365AccessToken>;
}

export interface M365ClientCredentials
  extends MS365ClientCredentials,
    M365AuthenticationMethod {}

export interface M365ClientCertificate
  extends MS365CertificateCredentials,
    M365AuthenticationMethod {}

export type M365Authentication = M365ClientCredentials | M365ClientCertificate;

const getJwtAlgFromPrivateKey = (
  privateKey: CryptoKey,
): { alg: string } => {
  const keyAlg: any = privateKey.algorithm;

  // RSA Client-Credentials with certificate typically uses RS256/384/512.
  if (keyAlg?.name !== "RSASSA-PKCS1-v1_5") {
    throw new Error(
      `Unsupported private key algorithm for M365 client assertion: ${keyAlg?.name ?? "unknown"}.`,
    );
  }

  const hashName: string | undefined = keyAlg?.hash?.name;
  switch (hashName) {
    case "SHA-256":
      return { alg: "RS256" };
    case "SHA-384":
      return { alg: "RS384" };
    case "SHA-512":
      return { alg: "RS512" };
    default:
      throw new Error(
        `Unsupported RSA signing hash for M365 client assertion: ${hashName ?? "unknown"}.`,
      );
  }
};

const getM365ClientCertificateClientAssertion = async (
  credentials: MS365CertificateCredentials,
): Promise<string> => {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj) throw new Error("WebCrypto API (globalThis.crypto) is not available.");

  const { alg } = getJwtAlgFromPrivateKey(credentials.privateKey);

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 600; // 10 minutes is usually accepted for client assertions

  const jti =
    typeof cryptoObj.randomUUID === "function"
      ? cryptoObj.randomUUID()
      : `${iat}-${Math.random().toString(16).slice(2)}`;

  const tokenEndpoint = `https://login.microsoftonline.com/${credentials.tenantId}/oauth2/v2.0/token`;

  // Client assertion JWT for OAuth2 client_credentials (RFC 7523).
  // Using jose ensures correct JWT header/payload/base64url handling.
  return await new SignJWT({})
    .setProtectedHeader({ alg, typ: "JWT" })
    .setIssuer(credentials.clientId)
    .setSubject(credentials.clientId)
    .setAudience(tokenEndpoint)
    .setJti(jti)
    .setIssuedAt(iat)
    .setNotBefore(iat)
    .setExpirationTime(exp)
    .sign(credentials.privateKey);
};

const getM365AccessTokenFromClientCertificate = async (
  credentials: MS365CertificateCredentials,
  scope: string = MS365Scopes.DEFAULT,
): Promise<M365AccessToken> => {
  const clientAssertion = await getM365ClientCertificateClientAssertion(credentials);

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

  const data = await response.json();
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
  const data = await response.json();
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
