/*
 * Licensed to the Sakai Foundation (SF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The SF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.sakaiproject.nakamura.oauthDemo;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.amber.oauth2.client.response.OAuthAuthzResponse;
import org.apache.amber.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.amber.oauth2.common.message.types.GrantType;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.sakaiproject.nakamura.api.lite.Session;
import org.sakaiproject.nakamura.api.lite.StorageClientException;
import org.sakaiproject.nakamura.api.lite.StorageClientUtils;
import org.sakaiproject.nakamura.api.lite.accesscontrol.AccessDeniedException;
import org.sakaiproject.nakamura.api.lite.content.Content;
import org.sakaiproject.nakamura.api.lite.content.ContentManager;
import org.sakaiproject.nakamura.util.LitePersonalUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.ImmutableMap;



@SlingServlet(methods = { "GET","POST" }, paths = { "/system/sling/oauthDemoVerifier" })
@Properties(value = {
    @Property(name = "service.description", value = "The Sakai Foundation"),
    @Property(name = "service.vendor", value = "The Sakai Foundation") })
public class OAuthDemoVerifyServlet extends SlingAllMethodsServlet {
  private static final Logger LOGGER = LoggerFactory
      .getLogger(OAuthDemoVerifyServlet.class);

  /**
	 * 
	 */
  private static final long serialVersionUID = 1L;

  // TODO require this be provided in the configuration
  public static final String DEFAULT_TOKEN_LOCATION = "https://accounts.google.com/o/oauth2/token";
  @Property(value = OAuthDemoVerifyServlet.DEFAULT_TOKEN_LOCATION)
  static final String TOKEN_LOCATION = "tokenLocation";

  // TODO require this be provided in the configuration
  public static final String DEFAULT_CLIENT_ID = "215879716306.apps.googleusercontent.com";
  @Property(value = OAuthDemoVerifyServlet.DEFAULT_CLIENT_ID)
  static final String CLIENT_ID = "clientId";
  
  // TODO require this be provided in the configuration
  public static final String DEFAULT_CLIENT_SECRET = "NIsboWRtRfthhZMobVLGeis0";
  @Property(value = OAuthDemoVerifyServlet.DEFAULT_CLIENT_SECRET)
  static final String CLIENT_SECRET = "clientSecret";
  
  public static final String DEFAULT_REDIRECT_URI = "http://localhost:8080/system/sling/oauthDemoVerifier";
  @Property(value = OAuthDemoVerifyServlet.DEFAULT_REDIRECT_URI)
  static final String REDIRECT_URI = "redirectUri";
  
  private String tokenLocation;
  private String clientId;
  private String clientSecret;
  private String redirectUri;
  private OAuthParams oAuthParams;
  
  @Activate
  protected void activate(Map<?, ?> props) {
    tokenLocation = PropertiesUtil.toString(props.get(TOKEN_LOCATION), DEFAULT_TOKEN_LOCATION);
    clientId = PropertiesUtil.toString(props.get(CLIENT_ID), DEFAULT_CLIENT_ID);
    clientSecret = PropertiesUtil.toString(props.get(CLIENT_SECRET), DEFAULT_CLIENT_SECRET);
    redirectUri = PropertiesUtil.toString(props.get(REDIRECT_URI), DEFAULT_REDIRECT_URI);
    oAuthParams = new OAuthParams(clientId, clientSecret, redirectUri);
  }
  
  @SuppressWarnings("unused")
  private OAuthClientRequest setTokenQuery(String code){  
    OAuthClientRequest  oar_request = null;
   try {
      oar_request = OAuthClientRequest
         .tokenLocation(tokenLocation)
         .setCode(code)
         .setClientId(clientId)
         .setClientSecret(clientSecret)
         .setRedirectURI(redirectUri)
         .setGrantType(GrantType.AUTHORIZATION_CODE)
         .buildBodyMessage();
     
   } catch (OAuthSystemException e) {
     LOGGER.error(e.getMessage(), e);
   }
    return oar_request;
    
  } 
 
  protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
      throws ServletException, IOException {
    try {
		dispatch(request,response);
	} catch (StorageClientException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (AccessDeniedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
  }
  
  protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response)
      throws ServletException, IOException {
    try {
		dispatch(request,response);
	} catch (StorageClientException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (AccessDeniedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}     
  }
  
  private String getCode(SlingHttpServletRequest request){
    OAuthAuthzResponse oar = null;
    try {
      oar = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
      oar.getExpiresIn();
    } catch (OAuthProblemException e) {
      LOGGER.error(e.getMessage(), e);
    }
    String code = oar.getCode();
    oAuthParams.setAuthzCode(code);
    return code;
  }
  
  private void dispatch(SlingHttpServletRequest request, SlingHttpServletResponse response)
      throws ServletException, IOException, StorageClientException, AccessDeniedException {
	String code = getCode(request);
	response.getWriter().append("\n GET ACCESS TOKEN \n");

    response.getWriter().append( "- Auth code: " +  code + " " + oAuthParams.getAuthzCode()  +"\n");

    try {
      OAuthClientRequest oauthRequest = OAuthClientRequest
          .tokenLocation(tokenLocation)
          .setCode(code)
          .setClientId(clientId)
          .setClientSecret(clientSecret)
          .setRedirectURI(redirectUri)
          .setGrantType(GrantType.AUTHORIZATION_CODE)
          .buildBodyMessage();
      
      OAuthClient client = new OAuthClient(new URLConnectionClient());
      Class<? extends OAuthAccessTokenResponse> cl = OAuthJSONAccessTokenResponse.class;
      OAuthAccessTokenResponse oauthResponse = client.accessToken(oauthRequest, cl);
      
      oAuthParams.setAccessToken(oauthResponse.getAccessToken());
      oAuthParams.setRefreshToken(oauthResponse.getRefreshToken());
      oAuthParams.setExpiresIn(oauthResponse.getExpiresIn());

      response.getWriter().append("- Access Token: " + oauthResponse.getAccessToken() + "\n");
      response.getWriter().append("- Refresh Token: " + oauthResponse.getRefreshToken() + "\n");
      response.getWriter().append("- Expires in: " + oauthResponse.getExpiresIn() + "\n");

      response.getWriter().append("\n\n GET RESOURCE \n");
      response.getWriter().append("- Resource: " + getResource(oAuthParams.getAccessToken())+"\n");
      
      //TODO: Require if the token is expired 
      if(oAuthParams.getRefreshToken()!=null){
    	  refreshToken(oauthResponse.getRefreshToken(),response);
      }
      
      storeTokens(request, oAuthParams.getAccessToken(), response);
      
    } catch (OAuthSystemException e) {
      LOGGER.error(e.getMessage(), e);
    } catch (OAuthProblemException e) {
      LOGGER.error(e.getMessage(), e);
    }
  }
  
  @SuppressWarnings("unused")
  private void dispatch2(String code , SlingHttpServletResponse response){
    String urlParameters = "code="+ code+
    		"&client_id="+ clientId + 
    		"&client_secret="+ clientSecret + 
    		"&redirect_uri="+ redirectUri + 
        "&grant_type=" + "authorization_code";
    
    String request = tokenLocation;
    URL url;
    try {
      url = new URL(request);
      URLConnection connection = url.openConnection();       
      connection.setDoOutput(true);
      connection.setDoInput(true);
      connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded"); 
      connection.setRequestProperty("charset", "utf-8");
      connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));
      connection.setUseCaches (false);

      DataOutputStream wr = new DataOutputStream(connection.getOutputStream ());
      wr.writeBytes(urlParameters);
      wr.flush();
      
      // Get the response
      response.getWriter().write("Oauth response: ");
      BufferedReader rd = new BufferedReader(new InputStreamReader(connection.getInputStream()));
      String line, message="";
      while ((line = rd.readLine()) != null) {
        message += line;
        response.getWriter().append(line);
      }
      response.getWriter().append("\n");
      String access_token = getAccessToken(message);
      response.getWriter().append("Access token: " + access_token + "\n");
      response.getWriter().append("Get resource: " + getResource(access_token)+"");
      rd.close();
      wr.close();
      
    } catch (MalformedURLException e) {
      LOGGER.error(e.getMessage(), e);
    } catch (IOException e) {
      LOGGER.error(e.getMessage(), e);
    } 

  }
  
  private String getAccessToken(String message) {
    Pattern pattern = Pattern.compile("access_token\" : \"[^\"]+");
    String cleanPattern = "access_token\" : \"";
    Matcher matcher = pattern.matcher(message);
    if (matcher.find()){
      String access_token = matcher.group(); 
      return access_token.replaceAll(cleanPattern, "");
      
    }
    return null; 
  }

  private String getResource(String accessToken){
    URL url;
    try {
      url = new URL("https://www.googleapis.com/oauth2/v1/userinfo?access_token="+accessToken);
      URLConnection con = url.openConnection();
      BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));

      String line, resource= "";
      while ((line = in.readLine()) != null) {
        resource+= line;
      }
      return resource;

    } catch (MalformedURLException e) {
      LOGGER.error(e.getMessage(), e);
    } catch (IOException e) {
      LOGGER.error(e.getMessage(), e);
    }
    return null;
    
  }
  
  private void refreshToken(String refreshToken, SlingHttpServletResponse response){

	  try {
		  response.getWriter().append("\n\n REFRESH TOKEN \n");

	      OAuthClientRequest oauthRequest = OAuthClientRequest
	          .tokenLocation(tokenLocation)
	          .setClientId(clientId)
	          .setClientSecret(clientSecret)
	          .setRefreshToken(refreshToken)
	          .setGrantType(GrantType.REFRESH_TOKEN)
	          .buildBodyMessage();
	      
	      OAuthClient client = new OAuthClient(new URLConnectionClient());
	      Class<? extends OAuthAccessTokenResponse> cl = OAuthJSONAccessTokenResponse.class;
	      OAuthAccessTokenResponse oauthResponse = client.accessToken(oauthRequest, cl);
	      
	      response.getWriter().append("- Access Token: " + oauthResponse.getAccessToken()+"\n");
	      response.getWriter().append("- Expires in: " + oauthResponse.getExpiresIn()+"\n");
	      
	      response.getWriter().append("\n\n GET RESOURCE");
	      response.getWriter().append("- Get resource: " + getResource(oAuthParams.getAccessToken())+"\n");
	      
	    } catch (OAuthSystemException e) {
	        LOGGER.error(e.getMessage(), e);
	      } catch (OAuthProblemException e) {
	        LOGGER.error(e.getMessage(), e);
	      } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

  }
  
  private void storeTokens(SlingHttpServletRequest request, String authorizationToken, SlingHttpServletResponse response)
      throws StorageClientException, AccessDeniedException, IOException {
	  
	response.getWriter().append("\n\n STORE TOKENS ");
    Session session = StorageClientUtils.adaptToSession(request.getResourceResolver()
        .adaptTo(javax.jcr.Session.class));
    ContentManager cm = session.getContentManager();
	response.getWriter().append("\n Get Remote user: " + request.getRemoteUser());
	
	if(request.getRemoteUser().equals("anonymous")){
		response.getWriter().append("\n Sorry we cann't store data since you are not logged");
	}
	else{
		String path = LitePersonalUtils.getPrivatePath(request
				.getRemoteUser()) + "/oauth";
		Map<String, Object> props = ImmutableMap.<String, Object> of("authorization_token", authorizationToken);
		Content content = new Content(path, props);
    	cm.update(content);
    }
  }
  
  
  private void storeTokensOffline(SlingHttpServletRequest request, String authorizationToken, String refreshToken)
      throws StorageClientException, AccessDeniedException {
    Session session = StorageClientUtils.adaptToSession(request.getResourceResolver()
        .adaptTo(javax.jcr.Session.class));
    ContentManager cm = session.getContentManager();
    String path = LitePersonalUtils.getPrivatePath(request
        .getRemoteUser()) + "/oauth";
    Map<String, Object> authorizationTokenProp = ImmutableMap.<String, Object> of("authorization_token",
        authorizationToken);
    Map<String, Object> refreshTokenProp = ImmutableMap.<String, Object> of("authorization_token",
        refreshToken);

    Content authorizationTokenCont = new Content(path, authorizationTokenProp);
    Content refreshTokenCont = new Content(path, refreshTokenProp);
    cm.update(authorizationTokenCont);
    cm.update(refreshTokenCont);

  }

}
