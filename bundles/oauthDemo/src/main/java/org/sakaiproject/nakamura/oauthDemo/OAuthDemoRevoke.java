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

import org.apache.amber.oauth2.client.OAuthClient;
import org.apache.amber.oauth2.client.URLConnectionClient;
import org.apache.amber.oauth2.client.request.OAuthClientRequest;
import org.apache.amber.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.amber.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.amber.oauth2.common.exception.OAuthProblemException;
import org.apache.amber.oauth2.common.exception.OAuthSystemException;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.sling.SlingServlet;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.commons.osgi.PropertiesUtil;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;

/**
 * The <code>OauthServerServlet</code> says Hello World (for the moment)
 */

@SlingServlet(methods = { "GET", "POST" }, paths = "/system/sling/oauthDemoRevoke", generateComponent = false)
@Component(metatype = true)
public class OAuthDemoRevoke extends SlingAllMethodsServlet {

	// TODO require this be provided in the configuration
	public static final String DEFAULT_REVOKE_LOCATION = "https://accounts.google.com/o/oauth2/revoke";
	@Property(value = OAuthDemoRevoke.DEFAULT_REVOKE_LOCATION)
	static final String REVOKE_LOCATION = "authorizationLocation";

	private static final Logger LOGGER = LoggerFactory
			.getLogger(OAuthDemoRevoke.class);
	private static final long serialVersionUID = -2002186252317448037L;

	private String revokeLocation;

	@Activate
	protected void activate(Map<?, ?> props) {
		revokeLocation = PropertiesUtil.toString(props.get(REVOKE_LOCATION),
				DEFAULT_REVOKE_LOCATION);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws ServletException,
			IOException {
		dispatch(request, response);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @see org.apache.sling.api.servlets.SlingAllMethodsServlet#doPost(org.apache.sling.api.SlingHttpServletRequest,
	 *      org.apache.sling.api.SlingHttpServletResponse)
	 */
	protected void doPost(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws ServletException,
			IOException {
		dispatch(request, response);
	}

	private String getTokens(SlingHttpServletRequest request,
			SlingHttpServletResponse response) throws StorageClientException,
			AccessDeniedException {

		Session session = StorageClientUtils.adaptToSession(request
				.getResourceResolver().adaptTo(javax.jcr.Session.class));
		ContentManager cm = session.getContentManager();
		Content privateOAuthPath = cm.get(LitePersonalUtils
				.getPrivatePath(request.getRemoteUser()) + "/oauth");

		if (privateOAuthPath != null) {
			String authorization_token = (String) privateOAuthPath
					.getProperty("authorization_token");
			return authorization_token;
		} else {
			return null;
		}
	}

	/**
	 * Dispatches a request to revoke the OAuth permissions.
	 * 
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void dispatch(SlingHttpServletRequest request, SlingHttpServletResponse response) 
			throws ServletException, IOException {
		response.getWriter().append("\n REVOKE LOCATION");

		String auth_token = null;
		try {
			auth_token = getTokens(request, response);
		} catch (StorageClientException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (AccessDeniedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		if (auth_token != null) {
			try {
				OAuthClientRequest oauthRequest = OAuthClientRequest
						.tokenLocation(revokeLocation)
						.setParameter("token", auth_token).buildBodyMessage();

				OAuthClient client = new OAuthClient(new URLConnectionClient());
				Class<? extends OAuthAccessTokenResponse> cl = OAuthJSONAccessTokenResponse.class;

				client.accessToken(oauthRequest, cl);

			} catch (OAuthSystemException e) {
				LOGGER.error(e.getMessage(), e);
			} catch (OAuthProblemException e) {
				LOGGER.error(e.getMessage(), e);
			}
		}
	}

}
