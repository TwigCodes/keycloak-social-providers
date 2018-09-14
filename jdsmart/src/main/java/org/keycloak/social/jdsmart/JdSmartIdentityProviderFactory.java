package org.keycloak.social.jdsmart;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.KeycloakSession;

public class JdSmartIdentityProviderFactory
  extends AbstractIdentityProviderFactory<JdSmartIdentityProvider>
  implements SocialIdentityProviderFactory<JdSmartIdentityProvider>{

    public static final String PROVIDER_ID = "jdsmart";

    @Override
    public String getName() {
        return "JdSmart";
    }

    @Override
    public JdSmartIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new JdSmartIdentityProvider(session, new OAuth2IdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}