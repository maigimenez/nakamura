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

@SlingServlet(methods = { "GET"}, paths = "/system/sling/oauthDemoPrivate", generateComponent = false)
@Component(metatype = true)
public class OAuthDemoPrivateServlet extends SlingAllMethodsServlet {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(OAuthDemoPrivateServlet.class);
	private static final long serialVersionUID = -2002186252317448037L;


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


	
	private String getTokens(SlingHttpServletRequest request,SlingHttpServletResponse response)
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
			SlingHttpServletResponse response) throws ServletException,
			IOException {

		String access_token = null;

		try {
			access_token = getTokens(request, response);
			response.getWriter().write("\n\n GET TOKENS \n" + getTokens(request, response));
		} catch (StorageClientException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (AccessDeniedException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		if (access_token == null) {
			response.getWriter().append("\n These are not the androids you're looking for");
		} else {
			response.getWriter().append("\n Get resource: " + getResource(access_token) + "");
		}
	}

	private String getResource(String accessToken) {
		URL url;
		try {
			url = new URL(
					"https://www.googleapis.com/oauth2/v1/userinfo?access_token="
							+ accessToken);
			URLConnection con = url.openConnection();
			BufferedReader in = new BufferedReader(new InputStreamReader(
					con.getInputStream()));

			String line, resource = "";
			while ((line = in.readLine()) != null) {
				resource += line;
			}
			return resource;

		} catch (MalformedURLException e) {
			LOGGER.error(e.getMessage(), e);
		} catch (IOException e) {
			LOGGER.error(e.getMessage(), e);
		}
		return null;

	}


}
