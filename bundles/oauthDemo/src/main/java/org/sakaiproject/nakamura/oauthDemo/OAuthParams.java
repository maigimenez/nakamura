/**
 *       Copyright 2010 Newcastle University
 *
 *          http://research.ncl.ac.uk/smart/
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.sakaiproject.nakamura.oauthDemo;


/**
 *
 *
 *
 */
public class OAuthParams {

    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String authzEndpoint;
    private String tokenEndpoint;
    private String authzCode;
    private String accessToken;
    private long expiresIn;
    private String refreshToken;
    private String scope;
    private String resourceUrl;
    private String resource;
    private String application;

    private String errorMessage;

    public OAuthParams(String clientId, String clientSecret,
			String redirectUri, String authzEndpoint, String tokenEndpoint,
			String authzCode, String accessToken, long expiresIn,
			String refreshToken, String scope, String resourceUrl,
			String resource, String application, String errorMessage) {
		super();
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.redirectUri = redirectUri;
		this.authzEndpoint = authzEndpoint;
		this.tokenEndpoint = tokenEndpoint;
		this.authzCode = authzCode;
		this.accessToken = accessToken;
		this.expiresIn = expiresIn;
		this.refreshToken = refreshToken;
		this.scope = scope;
		this.resourceUrl = resourceUrl;
		this.resource = resource;
		this.application = application;
		this.errorMessage = errorMessage;
	}
    
    public OAuthParams() {
		super();
		this.clientId = null;
		this.clientSecret = null;
		this.redirectUri = null;
		this.authzEndpoint = null;
		this.tokenEndpoint = null;
		this.authzCode = null;
		this.accessToken = null;
		this.expiresIn = -1;
		this.refreshToken = null;
		this.scope = null;
		this.resourceUrl = null;
		this.resource = null;
		this.application = null;
		this.errorMessage = null;
	}
    
    public OAuthParams(String clientId, String clientSecret,
			String redirectUri) {
		super();
		this.clientId = clientId;
		this.clientSecret = clientSecret;
		this.redirectUri = redirectUri;
		this.authzEndpoint = null;
		this.tokenEndpoint = null;
		this.authzCode = null;
		this.accessToken = null;
		this.expiresIn = -1;
		this.refreshToken = null;
		this.scope = null;
		this.resourceUrl = null;
		this.resource = null;
		this.application = null;
		this.errorMessage = null;
	}
	public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getAuthzEndpoint() {
        return authzEndpoint;
    }

    public void setAuthzEndpoint(String authzEndpoint) {
        this.authzEndpoint = authzEndpoint;
    }

    public String getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public String getAuthzCode() {
        return authzCode;
    }

    public void setAuthzCode(String authzCode) {
        this.authzCode = authzCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {
        this.expiresIn = Long.parseLong(expiresIn);
    }
    
    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getResourceUrl() {
        return resourceUrl;
    }

    public void setResourceUrl(String resourceUrl) {
        this.resourceUrl = resourceUrl;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getApplication() {
        return application;
    }

    public void setApplication(String application) {
        this.application = application;
    }
}
