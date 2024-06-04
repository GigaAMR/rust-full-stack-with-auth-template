use std::{env, collections::HashMap, sync::Arc, time::SystemTime};

use axum::{
    extract::{Request, State}, http::StatusCode, middleware, routing::{get, post}, Json, Router
};
use bcrypt::verify;
use email_address::EmailAddress;
use futures::lock::Mutex;
use http::{header::AUTHORIZATION, HeaderMap, HeaderValue};
use lettre::{message::header::ContentType, Message};
use rand::distributions::Alphanumeric;
use rand::Rng;
use types::{auth::{AuthErrorType, AuthToken}, user::{LoginUser, RegisterUser, UserInfo}};

use crate::{middleware::token_authentication, strategies::{authentication::{AuthClaims, AuthError, AuthRequesterClaims, Claims}, users}};

struct TimeStampedEmail {
    time_stamp: SystemTime,
    email: EmailAddress
}
struct ResetKeysState {
    keys: Mutex<HashMap<String, TimeStampedEmail>>
}

// route function to nest endpoints in router
pub fn routes() -> Router {
    let keys = Mutex::new(HashMap::<String, TimeStampedEmail>::new());
    let key_state = Arc::new(ResetKeysState{keys});
    // create routes
    Router::new()
        // create nested router for routes requiring AuthClaims
        .nest("/test", Router::new()
            .route("/", get(test_auth_route)))
            .layer(middleware::from_fn(token_authentication::authenticate_token::<AuthClaims>))
        // create nested router for routes requiring AuthRequesterClaims
        .nest("/request", Router::new()
            .route("/",get(request_auth_token))
            .layer(middleware::from_fn(token_authentication::authenticate_token::<AuthRequesterClaims>)))
        // routes that do not need middleware
        .route("/login", post(login_user))
        .route("/register", post(register_user))
        .route("/reset", post(request_reset))
        .with_state(key_state)
}

async fn test_auth_route(request: Request) -> Result<(StatusCode, String), AuthError> {
    // generate AuthClaims from encoded x-claim header
    let claims = AuthClaims::from_header(request.headers());
    println!("Authentication claims: {:?}", claims);
    // return with OK Status and body containing verified response
    Ok((StatusCode::OK, "Auth verified".to_string()))
}

async fn request_auth_token(request: Request) -> Result<(StatusCode, HeaderMap), AuthError> {
    // generate AuthRequesterClaims from encoded x-claim header
    let claims = AuthRequesterClaims::from_header(request.headers());
    // generate new AuthClaims token from UUID in AuthRequesterClaims
    if let Ok(auth_claims) = AuthClaims::new(claims.sub.clone()).await {
        let token_result = auth_claims.generate_token();
        let auth_token: AuthToken;
        match token_result {
            Ok(token) => auth_token = token,
            Err(error) => {
                println!("Error creating token for UUID {}: {:?}", claims.sub, error);
                return Err(error)
            }
        }
        // insert newly generated token into Authorization header
        let mut header_map = HeaderMap::new();
        header_map.insert(AUTHORIZATION, HeaderValue::from_str(&auth_token.to_string()).unwrap());
        // respond to request with token in header
        Ok((StatusCode::CREATED, header_map.clone()))
    } else {
        Err(AuthError::from_error_type(AuthErrorType::AccessDenied))
    }
}

// route for logging in user with provided LoginUser json
async fn login_user(
    Json(payload): Json<LoginUser>,
) -> Result<(StatusCode, HeaderMap, Json<UserInfo>), AuthError> {
    // check if supplied credentials are not empty
    if payload.username.is_empty() || payload.pass.is_empty() {
        return Err(AuthError::from_error_type(AuthErrorType::WrongCredentials));
    }
    // get user by username from database
    let result = users::get_db_user_by_username_or_email(payload.username).await;
    // if can't get user by username, return 400
    if let Err(_) = result {
        return Err(AuthError::from_error_type(AuthErrorType::UserDoesNotExist));
    }
    // unwrap result from DB as user object
    let user = result.unwrap();
    // verify supplied password is validated
    if verify(payload.pass, &user.pass).unwrap() {
        // build response user
        let user_info = UserInfo::from_user(user);
        // generate token from UserInfo uuid
        let token_result = AuthRequesterClaims::new(user_info.uuid.clone()).await.unwrap().generate_token();
        let auth_token: AuthToken;
        match token_result {
            Ok(token) => auth_token = token,
            Err(error) => return Err(error)
        }
        // insert newly generated token into Authorization header
        let mut header_map = HeaderMap::new();
        header_map.insert(AUTHORIZATION, HeaderValue::from_str(&auth_token.to_string()).unwrap());
        // respond to request with UserInfo in body
        Ok((StatusCode::CREATED, header_map.clone(), axum::Json(user_info)))
    } else {
        // respond with wrong credentials error
        return Err(AuthError::from_error_type(AuthErrorType::WrongCredentials));
    }
}


// handler for creating a new user
async fn register_user(
    Json(payload): Json<RegisterUser>,
) -> Result<(StatusCode, HeaderMap, Json<UserInfo>), AuthError> {
    if payload.username.is_empty() || payload.pass.is_empty() || payload.email.is_empty() {
        return Err(AuthError::from_error_type(AuthErrorType::MissingFields));
    }
    // validate email address before inserting
    if !EmailAddress::is_valid(&payload.email) {
        return Err(AuthError::from_error_type(AuthErrorType::InvalidEmail));
    }
    // insert user into table
    let db_result = users::insert_db_user(payload).await;
    // handle db errors
    if let Err(error) = db_result {
        println!("Error creating user: {}", error);
        if error.to_string().contains("duplicate key") {
            return Err(AuthError::from_error_type(AuthErrorType::UserAlreadyExists))
        }
        return Err(AuthError::from_error_type(AuthErrorType::ServerError));
    }
    // unwrap returned User object
    let user = db_result.unwrap();
    // build UserInfo to return from User object
    let user_info = UserInfo::from_user(user);
    // generate token from UserInfo uuid
    let token_result = AuthRequesterClaims::new(user_info.uuid.clone()).await.unwrap().generate_token();
    let auth_token: AuthToken;
    match token_result {
        Ok(token) => auth_token = token,
        Err(error) => {
            println!("Error creating token for UUID {}: {:?}", user_info.uuid, error);
            return Err(AuthError::from_error_type(AuthErrorType::TokenCreation))
        }
    }
    // insert parsed token into headermap
    let mut header_map = HeaderMap::new();
    header_map.insert(AUTHORIZATION, HeaderValue::from_str(&auth_token.to_string()).unwrap());
    // respond to request with UserInfo in body
    Ok((StatusCode::CREATED, header_map.clone(), axum::Json(user_info)))
}

async fn request_reset(
    State(state): State<Arc<ResetKeysState>>,
    Json(email): Json<EmailAddress>
) -> Result<StatusCode, AuthError> {
    if let Err(_) = users::get_db_user_by_username_or_email(email.to_string()).await {
        return Err(AuthError::from_error_type(AuthErrorType::UserDoesNotExist));
    }
    let reset_key = gen_reset_key();
    let mut keys = state.keys.lock().await;
    let company_name =  env::var("COMPANY_NAME").unwrap();
    let company_domain =  env::var("COMPANY_DOMAIN").unwrap();
    keys.insert(reset_key, TimeStampedEmail{email: email.clone(), time_stamp: SystemTime::now()});
    
    Ok(StatusCode::CREATED)
}

fn gen_reset_key() -> String {
    rand::thread_rng()
    .sample_iter(&Alphanumeric)
    .take(8)
    .map(char::from)
    .collect()
}