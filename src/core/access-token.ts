import {
  type M365AccessToken,
  createM365ClientCertificate,
  createM365ClientCredentials,
} from "./auth";
import {
  createM365KeyVaultJwtSigner,
  getM365KeyVaultCertificate,
} from "./keyvault";
import { MS365Scopes } from "./scopes";

export interface M365NodeSigningAccessTokenRequest {
  tenantId: string;
  clientId: string;
  privateKey: string | CryptoKey;
  certificate: string;
  scope?: string;
}

export interface M365KeyVaultSigningAccessTokenRequest {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  keyVaultName: string;
  certificateName: string;
  keyName: string;
  scope?: string;
  keyVaultTenantId?: string;
  keyVaultClientId?: string;
  keyVaultClientSecret?: string;
  certificateVersion?: string;
  keyVersion?: string;
}

export const getM365AccessTokenWithNodeSigning = async (
  request: M365NodeSigningAccessTokenRequest,
): Promise<M365AccessToken> => {
  const auth = createM365ClientCertificate({
    tenantId: request.tenantId,
    clientId: request.clientId,
    privateKey: request.privateKey,
    certificate: request.certificate,
  });

  return await auth.GetAccessToken(request.scope ?? MS365Scopes.DEFAULT);
};

export const getM365AccessTokenWithKeyVaultSigning = async (
  request: M365KeyVaultSigningAccessTokenRequest,
): Promise<M365AccessToken> => {
  const keyVaultAuth = createM365ClientCredentials({
    tenantId: request.keyVaultTenantId ?? request.tenantId,
    clientId: request.keyVaultClientId ?? request.clientId,
    clientSecret: request.keyVaultClientSecret ?? request.clientSecret,
  });

  const keyVaultCertificate = await getM365KeyVaultCertificate({
    vaultName: request.keyVaultName,
    certificateName: request.certificateName,
    certificateVersion: request.certificateVersion,
    authentication: keyVaultAuth,
  });

  const keyVaultSigner = createM365KeyVaultJwtSigner({
    vaultName: request.keyVaultName,
    keyName: request.keyName,
    keyVersion: request.keyVersion,
    authentication: keyVaultAuth,
  });

  const auth = createM365ClientCertificate({
    tenantId: request.tenantId,
    clientId: request.clientId,
    certificate: keyVaultCertificate.x509Pem,
    keyVaultSigner,
    keyId: keyVaultSigner.keyId,
  });

  return await auth.GetAccessToken(request.scope ?? MS365Scopes.DEFAULT);
};

