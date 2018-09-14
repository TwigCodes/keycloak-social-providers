package org.keycloak.social.jdsmart;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

public class JdSmartIdentityProvider
    extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
    implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {
  private static final String DEFAULT_TIME_STAMP_FORMAT = "yyyy-MM-dd HH:mm:ss";
  private static final String DEFAULT_TIME_ZONE = "Asia/Shanghai";
  private static final String PLATFORM = "ios";
  private static final String ANDROID_PACKAGE_NAME = "com.sc.smarthome";
  private static final String ANDROID_SHA1_SIGNATURE = "C7DAB911032E9E6CD2FBAB01F324A9B37D452F8B";
  private static final String IOS_BUNDLE_ID = "com.sc.smart";
  private static final String OAUTH2_PARAMETER_IDENTITY = "identity";
  private static final String OAUTH2_PARAMETER_PLATFORM = "plat";
  private static final String OAUTH2_PARAMETER_TIMESTAMP = "timestamp";
  private static final String DEVICE_PLATFORM = "ios";

  public static final String BASE_AUTH_URL = "https://smartopen.jd.com/oauth/authorize";
  public static final String TOKEN_URL = "https://smartopen.jd.com/oauth/token";
  public static final String DEFAULT_SCOPE = "read";

  public JdSmartIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
    super(session, config);
    config.setAuthorizationUrl(BASE_AUTH_URL);
    config.setTokenUrl(TOKEN_URL);
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new Endpoint(callback, realm, event);
  }

  @Override
  protected boolean supportsExternalExchange() {
    return true;
  }

  @Override
  protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
    String uid = getJsonProperty(profile, "uid");
    BrokeredIdentityContext user = new BrokeredIdentityContext(uid);

    user.setUsername(getJsonProperty(profile, uid));
    user.setBrokerUserId(getJsonProperty(profile, uid));
    user.setName(getJsonProperty(profile, "user_nick"));
    user.setIdpConfig(getConfig());
    user.setIdp(this);
    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
    return user;
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {
    try {
      URI authorizationUrl = createAuthorizationUrl(request).build();
      return Response.seeOther(authorizationUrl).build();
    } catch (Exception e) {
      throw new IdentityBrokerException("Could not create authentication request.", e);
    }
  }

  @Override
  protected String getDefaultScopes() {
    return DEFAULT_SCOPE;
  }

  @Override
  protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {

    final UriBuilder uriBuilder = UriBuilder.fromUri(BASE_AUTH_URL);
    logger.info("----------jdsmart");
    String clientId = getConfig().getClientId();
    String formatDateTime = getFormattedDate();
    String identity;
    try {
      identity = buildAppSignature(IOS_BUNDLE_ID, clientId, formatDateTime);
      uriBuilder
        .queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code")
        .queryParam(OAUTH2_PARAMETER_CLIENT_ID, clientId)
        .queryParam(OAUTH2_PARAMETER_REDIRECT_URI, request.getRedirectUri())
        .queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
        .queryParam(OAUTH2_PARAMETER_IDENTITY, identity)
        .queryParam(OAUTH2_PARAMETER_PLATFORM, DEVICE_PLATFORM)
        .queryParam(OAUTH2_PARAMETER_TIMESTAMP, formatDateTime);
        String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
      if (getConfig().isLoginHint() && loginHint != null) {
        uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
      }

      String prompt = getConfig().getPrompt();
      if (prompt == null || prompt.isEmpty()) {
        prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
      }
      if (prompt != null) {
        uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
      }

      String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
      if (nonce == null || nonce.isEmpty()) {
        nonce = UUID.randomUUID().toString();
        request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
      }
      uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

      String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
      if (acr != null) {
        uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
      }
    } catch (NoSuchAlgorithmException e) {
      logger.error("算法没有找到，抛出异常", e);
      throw new IdentityBrokerException("算法没有找到，抛出异常: " + e.getMessage());
    }
    return uriBuilder;
  }

  @Override
  public BrokeredIdentityContext getFederatedIdentity(String response) {
		BrokeredIdentityContext context = null;
		try {
			JsonNode profile = null;
			profile = new ObjectMapper().readTree(response);
			logger.info("get userInfo =" + profile.toString());
			context = extractIdentityFromProfile(null, profile);
		} catch (IOException e) {
			logger.error(e);
    }
    String accessToken = extractTokenFromResponse(response, "access_token");
		context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
		return context;
	}

  private static String buildAppSignature(String toBeHashed, String appKey, String timestamp)
      throws NoSuchAlgorithmException {
    String timeStampedSignature = toBeHashed + timestamp + appKey + timestamp;
    String digestedSignatureResult = buildDigest(timeStampedSignature, true);
    return digestedSignatureResult;
  }

  private static String buildDigest(String token, boolean isUpperCase) throws NoSuchAlgorithmException {
    MessageDigest md = MessageDigest.getInstance("MD5");
    md.update(token.getBytes());
    byte[] digest = md.digest();
    return isUpperCase ? toHex(digest).toUpperCase() : toHex(digest).toLowerCase();
  }

  public static String toHex(byte[] bytes) {
    BigInteger bi = new BigInteger(1, bytes);
    return String.format("%0" + (bytes.length << 1) + "X", bi);
}

  private static String getFormattedDate() {
    DateTimeFormatter formatter = DateTimeFormatter
      .ofPattern(DEFAULT_TIME_STAMP_FORMAT)
      .withZone(ZoneId.of(DEFAULT_TIME_ZONE));
    return formatter.format(Instant.now());
  }

  protected class Endpoint {
    protected AuthenticationCallback callback;
    protected RealmModel realm;
    protected EventBuilder event;

    @Context
    protected KeycloakSession session;

    @Context
    protected ClientConnection clientConnection;

    @Context
    protected HttpHeaders headers;

    @Context
    protected UriInfo uriInfo;

    public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
      this.callback = callback;
      this.realm = realm;
      this.event = event;
    }

    @GET
    public Response authResponse(
      @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
      @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
      @QueryParam(OAuth2Constants.ERROR) String error) {
      logger.info("OAUTH2_PARAMETER_CODE=" + authorizationCode);
      if (error != null) {
        // logger.error("Failed " + getConfig().getAlias() + " broker
        // login: " + error);
        if (error.equals(ACCESS_DENIED)) {
          logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
          return callback.cancelled(state);
        } else {
          logger.error(error + " for broker login " + getConfig().getProviderId());
          return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
        }
      }

      try {
        BrokeredIdentityContext federatedIdentity = null;
        if (authorizationCode != null) {
          String response = generateTokenRequest(authorizationCode).asString();
          logger.info("response=" + response);
          federatedIdentity = getFederatedIdentity(response);

          if (getConfig().isStoreToken()) {
            if (federatedIdentity.getToken() == null)
              federatedIdentity.setToken(response);
          }

          federatedIdentity.setIdpConfig(getConfig());
          federatedIdentity.setIdp(JdSmartIdentityProvider.this);
          federatedIdentity.setCode(state);

          return callback.authenticated(federatedIdentity);
        }
      } catch (WebApplicationException e) {
        return e.getResponse();
      } catch (Exception e) {
        logger.error("Failed to make identity provider oauth callback", e);
      }
      event.event(EventType.LOGIN);
      event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
      return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
    }

    public SimpleHttp generateTokenRequest(String authorizationCode) {
      return SimpleHttp.doPost(getConfig().getTokenUrl(), session)
        .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE)
        .param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
        .param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret())
        .param(OAUTH2_PARAMETER_REDIRECT_URI, uriInfo.getAbsolutePath().toString())
        .param(OAUTH2_PARAMETER_CODE, authorizationCode);
    }
  }
}