use std::{env, str::FromStr};

use gloo_console::error;
use gloo_storage::{Storage, errors::StorageError};
use once_cell::sync::OnceCell;
use reqwest::{header::{HeaderMap, AUTHORIZATION}, Client, RequestBuilder, Response, StatusCode, Url};
use types::auth::{AuthErrorBody, AuthErrorType, AuthToken};


pub mod auth;
pub mod user;

static HTTP_CLIENT: OnceCell<Client> = OnceCell::new();
static BASE_URL: OnceCell<String> = OnceCell::new();

pub fn create_http_clients() {
    let base_url = env::var("BASE_URL").unwrap_or("http://localhost:3001".to_string());
    BASE_URL.set(base_url).unwrap();
    HTTP_CLIENT.set(Client::builder()
    .build()
    .unwrap()).unwrap();
}

pub fn get_http_client() -> Client {
    HTTP_CLIENT.get().unwrap().to_owned()
}

pub fn get_base_url() -> String {
    BASE_URL.get().unwrap().to_owned()
}
#[derive(Debug)]
pub struct AuthRequest {
    token: AuthToken,
    request_builder: RequestBuilder
}

impl AuthRequest {
    pub fn new(request_builder: RequestBuilder) -> Self {
        let mut token = AuthStorage::get_auth_token();
        if let Err(_storage_error) = token {
            token = Ok(AuthToken::default());
        }
        return Self {
            token: token.unwrap(),
            request_builder
        }
    }
    async fn request_auth_token() -> Result<StatusCode, AuthError> {
        // Build auth header from token
        let auth_token_result = AuthStorage::get_requester_token();
        if let Err(_) = &auth_token_result {
            return Err(AuthError::from_error_type(AuthErrorType::InvalidToken))
        }
        let auth_token = auth_token_result.unwrap();
    
        // Build request for retrieving valid token with access information
        let request_builder = get_http_client()
            .get(get_base_url() + "/auth/request")
            .bearer_auth(auth_token.to_string());
        let request_result = request_builder.send().await;
        if let Err(error) = request_result {
            error!("Error with request: {}", error.to_string());
            return Err(AuthError::default());
        }
    
        // Unwrap response from request_result
        let response = request_result.unwrap();
    
        // Get status and match for responsive behavior
        let status = response.status();
    
        // Check if status is success
        if !status.is_success() {
            return Err(AuthError::from_response(response).await);
        }
    
        // Extract auth header from headers
        let headers = response.headers();
        let auth_header_result = headers.get(AUTHORIZATION);
        if let None = auth_header_result {
            return Err(AuthError::from_error_type(AuthErrorType::TokenCreation));
        }
        let header = auth_header_result.unwrap();
        let header_str = header.to_str().unwrap_or("");
    
        // Store auth token
        AuthStorage::store_auth_token(AuthToken::from_string(header_str.to_string()));
        Ok(status)
    }
    
    async fn refresh_token(&mut self) -> Result<(), AuthError> {
        let auth_request_result = AuthRequest::request_auth_token().await;
        if let Err(auth_error) = auth_request_result {
            return Err(auth_error);
        }
        let token = AuthStorage::get_auth_token();
        if let Err(_storage_error) = token {
            return Err(AuthError::from_error_type(AuthErrorType::InvalidToken));
        }
        self.token = token.unwrap();
        Ok(())
    }
    pub async fn send(&mut self) -> Result<Response, AuthError> {
        let refresh_result = self.refresh_token().await;
        if let Err(refresh_error) = refresh_result {
            return Err(refresh_error);
        }
        let response  = self.request_builder.try_clone().unwrap()
            .bearer_auth(self.token.clone().to_string())
            .send().await;
        if let Err(_error) = response {
            return Err(AuthError::from_error_type(AuthErrorType::BadRequest));
        }
        Ok(response.unwrap())
    }
}

pub struct AuthStorage;

impl AuthStorage {
    const TOKEN_KEY: &'static str = "AUTH_TOKEN";
    const REQUESTER_TOKEN_KEY: &'static str = "AUTH_REQUESTER_TOKEN";
    fn store(token_key: &str, token_string: &str) {
        gloo_storage::LocalStorage::set(token_key, token_string).unwrap();
    }
    fn store_from_headers(headers: &HeaderMap) {
        headers.get_all(AUTHORIZATION).into_iter().for_each(|header| {
            let header_str_result = header.to_str();
            if let Err(error) = &header_str_result {
                error!("Error converting header to str: {}", error.to_string());
            }
            let header_str = header_str_result.unwrap();
            AuthStorage::store_requester_token(AuthToken::from_string(header_str.to_string()));
        });
    }
    fn get(token_key: &str) -> Result<AuthToken, StorageError>  {
        match gloo_storage::LocalStorage::get(token_key) {
            Ok(token_string) => {
                Ok(AuthToken::from_string(token_string))
            },
            Err(storage_error) => Err(storage_error)
        }
    }
    pub fn clear() {
        gloo_storage::LocalStorage::delete(Self::TOKEN_KEY);
        gloo_storage::LocalStorage::delete(Self::REQUESTER_TOKEN_KEY);
    }
    pub fn get_requester_token() -> Result<AuthToken, StorageError> {
        Self::get(Self::REQUESTER_TOKEN_KEY)
    }
    pub fn get_auth_token() -> Result<AuthToken, StorageError> {
        Self::get(Self::TOKEN_KEY)
    }
    pub fn store_requester_token(token: AuthToken) {
        Self::store(Self::REQUESTER_TOKEN_KEY, &token.to_string());
    }
    pub fn store_auth_token(token: AuthToken) {
        Self::store(Self::TOKEN_KEY, &token.to_string());
    }
}

#[derive(Debug, Clone)]
pub struct AuthError(types::auth::AuthError);

impl AuthError {
    pub async fn from_response(response: Response) -> Self {
        let status: StatusCode = response.status();
        let error_body = response.json::<AuthErrorBody>().await;
        if let Err(_) = error_body {
            return Self {
                0: types::auth::AuthError::default()
            }
        }
        return Self  {
            0: types::auth::AuthError {
                status: http::StatusCode::from_str(status.as_str()).unwrap(),
                body: error_body.unwrap()
            }
        };
    }
    pub fn from_error_type(error_type: AuthErrorType) -> Self {
        Self {
            0: types::auth::AuthError::from_error_type(error_type)
        }
    }
    pub fn body(&self) -> AuthErrorBody {
        self.0.body.to_owned()
    }
    pub fn default() -> Self {
        Self {
            0: types::auth::AuthError::default()
        }
    }
}