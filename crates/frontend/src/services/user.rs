use reqwest::{Method, StatusCode, Url};
use types::user::UserInfo;

use super::{get_http_client, AuthRequest};

pub async fn get_user_info() -> UserInfo {
    let request_builder = AuthRequest::new(get_http_client()
        .request(Method::GET, Url::parse("http://localhost:3001/user/info").unwrap()));

    // Request user info from server
    let request_result = request_builder.send().await;
    if let Err(_) = request_result {
        return UserInfo::new();
    }

    let response = request_result.unwrap();
    
    // Parse response body as JSON
    let json_result = response.json::<UserInfo>().await;
    if let Err(_) = json_result {
        return UserInfo::new();
    }

    // Return UserInfo
    let data = json_result.unwrap();
    return data;
}

pub async fn get_all_users() -> Result<(StatusCode, Vec<UserInfo>), StatusCode> {
    let request_result = AuthRequest::new(get_http_client()
        .request(Method::GET, Url::parse("http://localhost:3001/user/all").unwrap()));
    // Unwrap request and extract status as owned value
    let response = request_result.send().await;
    if let Err(_) = response {
        return Err(StatusCode::UNAUTHORIZED)
    }
    let response = response.unwrap();
    let status = response.status();

    // Parse body as JSON
    let json_result = response.json::<Vec<UserInfo>>().await;
    if let Err(error) = json_result {
        return Err(error.status().unwrap_or_default());
    }

    // Return vec of users
    let users = json_result.unwrap();
    Ok((status, users))
}

pub async fn delete_user(uuid: String) -> Result<StatusCode, StatusCode> {
    let request = AuthRequest::new(get_http_client()
    .delete("http://localhost:3001/user")
    .body(uuid));
    // Request to delete user with uuid
    let request_result = request.send().await;
    if let Err(_) = request_result {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Unwrap request and extract status as owned value
    let response = request_result.unwrap();

    // Return status of response
    Ok(response.status())
}