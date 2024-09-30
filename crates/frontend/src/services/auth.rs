use gloo_console::{error, log};

use reqwest::StatusCode;
use types::user::{LoginUser, RegisterUser, ResetUser, UserInfo};

use super::{get_base_url, get_http_client, AuthError, AuthRequest, AuthStorage};

pub async fn test_auth_route() -> Result<StatusCode, AuthError> {
    let request_result = AuthRequest::new(
        get_http_client().get(get_base_url() + "/auth/test")
    ).send().await;
    // Send request to test auth route
    if let Err(_) = request_result {
        return Err(AuthError::default());
    }
    // Unwrap resonse from request_result
    let response = request_result.unwrap();
    let status = response.status();

    // Check if status is success
    if !status.is_success() {
        return Err(AuthError::from_response(response).await);
    }

    // Extract text from body and log to console
    let text_result = response.text().await;
    if let Err(error) = text_result {
        error!(format!("Error with parsing body as text: {error}"));
        Err(AuthError::default())
    } else {
        let text = text_result.unwrap();
        log!(format!("{text}"));
        Ok(status)
    }
}

pub async fn register_user(user: RegisterUser) -> Result<UserInfo, AuthError> {
    // Send register data to server
    let request_result = get_http_client()
        .post(get_base_url() + "/auth/register")
        .json(&user)
        .send().await;
    if let Err(error) = request_result {
        error!("Error with request: {}", error.to_string());
        return Err(AuthError::default());
    }

    // Unwrap response from request_result
    let response = request_result.unwrap();
    let status = response.status();

    // Check if status is success
    if !status.is_success() {
        return Err(AuthError::from_response(response).await);
    }

    // Extract auth requester token from headers and store in local browser storage
    let headers = response.headers();
    AuthStorage::store_from_headers(headers);

    // Extract user info from json body
    let json_result = response.json::<UserInfo>().await;
    if let Err(error) = json_result {
        error!("Error parsing body: {}", error.to_string());
        return Err(AuthError::default());
    }

    // Unwrap JSON result and return as OK result
    let data = json_result.unwrap();
    return Ok(data);
}

pub async fn login_user(user: LoginUser) -> Result<UserInfo, AuthError>  {
    // Send login data to server
    let request_result = get_http_client().post(get_base_url() + "/auth/login").json(&user).send().await;
    if let Err(error) = request_result {
        error!(format!("Error with request: {}", error.to_string()));
        return Err(AuthError::default());
    }

    // Unwrap response from request_result
    let response = request_result.unwrap();
    let status = response.status();

    // Check if status is success
    if !status.is_success() {
        return Err(AuthError::from_response(response).await);
    }

    // Extract auth requester token from headers and store in local browser storage
    let headers = response.headers();
    AuthStorage::store_from_headers(headers);

    // Extract user info from json body
    let json_result = response.json::<UserInfo>().await;
    if let Err(_) = json_result {
        return Err(AuthError::default());
    }

    // Unwrap JSON result and return as OK result
    let data = json_result.unwrap();
    return Ok(data);
}

pub async fn reset_user(user: ResetUser, key: String) -> Result<StatusCode, AuthError> {
    let request_result = get_http_client().post(get_base_url() + &format!("/auth/reset/{key}")).json(&user).send().await;
    if let Err(error) = request_result {
        error!("Error with request: {}", error.to_string());
        return Err(AuthError::default());
    }

    // Unwrap response from request_result
    let response = request_result.unwrap();
    let status = response.status();

    // Check if status is success
    if !status.is_success() {
        return Err(AuthError::from_response(response).await);
    }

    // Clear auth storage
    AuthStorage::clear();
    return Ok(status);
}

pub async fn request_reset(email: String) -> Result<StatusCode, AuthError> {
    let request_result = get_http_client().post(get_base_url() + "auth/reset").body(email).send().await;
    if let Err(error) = request_result {
        error!("Error with request: {}", error.to_string());
        return Err(AuthError::default());
    }

    // Unwrap response from request_result
    let response = request_result.unwrap();
    let status = response.status();

    // Check if status is success
    if !status.is_success() {
        return Err(AuthError::from_response(response).await);
    }

    // Clear auth storage
    AuthStorage::clear();
    return Ok(status);
}

pub fn logout_user() {
    // Clear local auth storage to remove auth tokens
    AuthStorage::clear();
}