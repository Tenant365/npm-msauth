import { MS365Scopes } from "./scopes";

export interface MS365ClientCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export type M365AccessToken = {
  token: string;
  expiresAt: Date;
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
        scope: "https://graph.microsoft.com/.default",
      }),
    },
  );
  const data = await response.json();
  return {
    token: data.access_token,
    expiresAt: new Date(Date.now() + data.expires_in * 1000),
  };
};
