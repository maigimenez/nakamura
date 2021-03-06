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

import org.sakaiproject.nakamura.api.lite.Session;
import org.sakaiproject.nakamura.api.lite.StorageClientException;
import org.sakaiproject.nakamura.api.lite.StorageClientUtils;
import org.sakaiproject.nakamura.api.lite.accesscontrol.AccessDeniedException;
import org.sakaiproject.nakamura.api.lite.content.Content;
import org.sakaiproject.nakamura.api.lite.content.ContentManager;
import org.sakaiproject.nakamura.util.LitePersonalUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.commons.osgi.PropertiesUtil;

import com.google.common.collect.ImmutableMap;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Map;

import javax.servlet.ServletException;

/**
 * The <code>OauthServerServlet</code> says Hello World (for the moment)
 */

@SlingServlet(methods = { "GET", "POST" }, paths = "/system/sling/oauthDemo", generateComponent = false)
@Component(metatype = true)
public class OAuthDemoServlet extends SlingAllMethodsServlet {

	// TODO require this be provided in the configuration
	public static final String DEFAULT_AUTHZ_LOCATION = "https://accounts.google.com/o/oauth2/auth";
	@Property(value = OAuthDemoServlet.DEFAULT_AUTHZ_LOCATION)
	static final String AUTHZ_LOCATION = "authorizationLocation";

	// TODO require this be provided in the configuration
	public static final String DEFAULT_SCOPE = "https://www.googleapis.com/auth/userinfo.profile";
	@Property(value = OAuthDemoServlet.DEFAULT_SCOPE)
	static final String SCOPE = "scope";

	// TODO require this be provided in the configuration
	public static final String DEFAULT_CLIENT_ID = "215879716306.apps.googleusercontent.com";
	@Property(value = OAuthDemoServlet.DEFAULT_CLIENT_ID)
	static final String CLIENT_ID = "clientId";

	// TODO require this be provided in the configuration
	public static final String DEFAULT_STATE = "/profile";
	@Property(value = OAuthDemoServlet.DEFAULT_STATE)
	static final String STATE = "state";

	public static final String DEFAULT_APPROVAL_PROMPT = "force";
	@Property(value = OAuthDemoServlet.DEFAULT_APPROVAL_PROMPT)
	static final String APPROVAL_PROMPT = "approvalPrompt";

	public static final String DEFAULT_REDIRECT_URI = "http://localhost:8080/system/sling/oauthDemoVerifier";
	@Property(value = OAuthDemoServlet.DEFAULT_REDIRECT_URI)
	static final String REDIRECT_URI = "redirectUri";

	public static final String DEFAULT_PROTECTED_RESOURCE_URI = "http://localhost:8080/system/sling/oauthDemoPrivate";
	@Property(value = OAuthDemoServlet.DEFAULT_PROTECTED_RESOURCE_URI)
	static final String PROTECTED_RESOURCE_URI = "resourceUri";
	
	public static final String DEFAULT_RESPONSE_TYPE = "code";
	@Property(value = OAuthDemoServlet.DEFAULT_RESPONSE_TYPE)
	static final String RESPONSE_TYPE = "responseType";

	private static final long serialVersionUID = -2002186252317448037L;

	private String authorizationLocation;
	private String scope;
	private String state;
	private String redirectUri;
	private String responseType;
	private String clientId;
	private String approvalPrompt;
	private String resourceUri;

	@Activate
	protected void activate(Map<?, ?> props) {
		authorizationLocation = PropertiesUtil.toString(props.get(AUTHZ_LOCATION), DEFAULT_AUTHZ_LOCATION);
		scope = PropertiesUtil.toString(props.get(SCOPE), DEFAULT_SCOPE);
		state = PropertiesUtil.toString(props.get(STATE), DEFAULT_STATE);
		redirectUri = PropertiesUtil.toString(props.get(REDIRECT_URI),DEFAULT_REDIRECT_URI);
		responseType = PropertiesUtil.toString(props.get(RESPONSE_TYPE),DEFAULT_RESPONSE_TYPE);
		clientId = PropertiesUtil.toString(props.get(CLIENT_ID),DEFAULT_CLIENT_ID);
		approvalPrompt = PropertiesUtil.toString(props.get(APPROVAL_PROMPT),DEFAULT_APPROVAL_PROMPT);
		resourceUri = PropertiesUtil.toString(props.get(PROTECTED_RESOURCE_URI),DEFAULT_PROTECTED_RESOURCE_URI);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws ServletException, IOException {
		dispatch(request, response);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see org.apache.sling.api.servlets.SlingAllMethodsServlet#doPost(org.apache.sling.api.SlingHttpServletRequest,
	 *      org.apache.sling.api.SlingHttpServletResponse)
	 */
	protected void doPost(SlingHttpServletRequest request, SlingHttpServletResponse response) 
			throws ServletException,IOException {
		dispatch(request, response);
	}
	
	
	/**
	 * Try to get authorization_token from a user than already has given its permission.
	 * 
	 * @param request
	 * @param response
	 * @throws StorageClientException
	 * @throws AccessDeniedException
	 */
	private String getTokens(SlingHttpServletRequest request)
			throws StorageClientException, AccessDeniedException {
		
		Session session = StorageClientUtils.adaptToSession(request
				.getResourceResolver().adaptTo(javax.jcr.Session.class));
		ContentManager cm = session.getContentManager();
		Content privateOAuthPath = cm.get(
				LitePersonalUtils.getPrivatePath(request.getRemoteUser())
				+ "/oauth");

		if (privateOAuthPath != null) {
			String authorization_token = (String) privateOAuthPath.getProperty("authorization_token");
			return authorization_token;
		} else {
			return null;
		}
	}

	/**
	 * Dispatches a redirect request to the OAuth server.
	 * 
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void dispatch(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws ServletException, IOException {

		String access_token = null;

		try {
			access_token = getTokens(request);
			response.getWriter().write("\n\n GET TOKENS \n" + getTokens(request));
		} catch (StorageClientException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (AccessDeniedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		if (access_token == null) {

			try {
				OAuthClientRequest oauthRequest = OAuthClientRequest
						.authorizationLocation(authorizationLocation)
						.setScope(scope).setState(state)
						.setRedirectURI(redirectUri)
						.setResponseType(responseType).setClientId(clientId)
						.setParameter("approval_prompt", approvalPrompt)
						.buildQueryMessage();
				response.sendRedirect(oauthRequest.getLocationUri());
			} catch (OAuthSystemException e) {
				throw new ServletException(e.getMessage(), e);
			}
		} else {
			response.sendRedirect(resourceUri);
		}
	}


	/**
	 * Dispatches a redirect request to the OAuth server, with offline access
	 * 
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void dispatchOffline(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws ServletException,
			IOException {
		try {
			OAuthClientRequest oauthRequest = OAuthClientRequest
					.authorizationLocation(authorizationLocation)
					.setScope(scope).setState(state)
					.setRedirectURI(redirectUri).setResponseType(responseType)
					.setClientId(clientId)
					.setParameter("access_type", "offline")
					.setParameter("approval_prompt", approvalPrompt)
					.buildQueryMessage();
			response.sendRedirect(oauthRequest.getLocationUri());
		} catch (OAuthSystemException e) {
			throw new ServletException(e.getMessage(), e);
		}
	}
}
