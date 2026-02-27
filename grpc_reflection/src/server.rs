//! src/server.rs
//!
//! This is the backend gRPC Microservice.
//! It implements the business logic defined in `system_services.proto` and, crucially,
//! exposes the gRPC Server Reflection endpoint so dynamic clients (like our Router)
//! can query its schema at runtime.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status, transport::Server};
use tonic_reflection::server::Builder as ReflectionBuilder;

// This module includes the Rust code that `build.rs` automatically generated
// from our `system_services.proto` file.
pub mod system {
    tonic::include_proto!("system");
}

// Import generated traits and servers
use system::identity_service_server::{IdentityService, IdentityServiceServer};
use system::store_service_server::{StoreService, StoreServiceServer};
use system::system_metrics_server::{SystemMetrics, SystemMetricsServer};
// Import generated types
use system::{
    AuthTokenResponse, HealthStatus, LoginRequest, MetricsQuery, RetrieveRequest, RetrieveResponse,
    StoreRequest, StoreResponse,
};

// LOAD THE DESCRIPTOR SET FOR REFLECTION
pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("system_services_descriptor");

// -----------------------------------------------------------------------------
// 1. Identity Service Implementation
// -----------------------------------------------------------------------------
#[derive(Default)]
pub struct MyIdentityService {}

#[tonic::async_trait]
impl IdentityService for MyIdentityService {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<AuthTokenResponse>, Status> {
        let req = request.into_inner();
        println!("IdentityService handling Login for user: {}", req.username);

        // Dummy authentication logic
        if req.username == "admin" && req.password == "admin123" {
            Ok(Response::new(AuthTokenResponse {
                token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_token".into(),
                expires_in_seconds: 3600,
            }))
        } else {
            Err(Status::unauthenticated("Invalid username or password"))
        }
    }
}

// -----------------------------------------------------------------------------
// 2. System Metrics Implementation
// -----------------------------------------------------------------------------
#[derive(Default)]
pub struct MySystemMetrics {}

#[tonic::async_trait]
impl SystemMetrics for MySystemMetrics {
    async fn get_health(
        &self,
        request: Request<MetricsQuery>,
    ) -> Result<Response<HealthStatus>, Status> {
        let req = request.into_inner();
        println!("SystemMetrics handling GetHealth request");

        let mut cpu = 0.0;
        let mut mem = 0.0;

        if req.include_cpu {
            cpu = 12.3; // Dummy data
        }
        if req.include_memory {
            mem = 1024.5;
        }

        Ok(Response::new(HealthStatus {
            status: "Healthy".into(),
            cpu_usage_percent: cpu,
            memory_usage_mb: mem,
            uptime_seconds: 86400,
        }))
    }
}

// -----------------------------------------------------------------------------
// 3. Stateful Store Service Implementation
// -----------------------------------------------------------------------------
#[derive(Default)]
pub struct MyStoreService {
    // Thread-safe map to hold global state between requests
    store: Arc<RwLock<HashMap<String, String>>>,
}

#[tonic::async_trait]
impl StoreService for MyStoreService {
    async fn store_data(
        &self,
        request: Request<StoreRequest>,
    ) -> Result<Response<StoreResponse>, Status> {
        let req = request.into_inner();
        println!("StoreService handling StoreData for key: {}", req.key);

        let mut map = self.store.write().await;
        map.insert(req.key.clone(), req.value.clone());

        Ok(Response::new(StoreResponse {
            success: true,
            message: format!("Successfully stored key '{}'", req.key),
        }))
    }

    async fn retrieve_data(
        &self,
        request: Request<RetrieveRequest>,
    ) -> Result<Response<RetrieveResponse>, Status> {
        let req = request.into_inner();
        println!("StoreService handling RetrieveData for key: {}", req.key);

        let map = self.store.read().await;
        if let Some(val) = map.get(&req.key) {
            Ok(Response::new(RetrieveResponse {
                found: true,
                value: val.clone(),
            }))
        } else {
            Ok(Response::new(RetrieveResponse {
                found: false,
                value: String::new(),
            }))
        }
    }
}

// -----------------------------------------------------------------------------
// Server Entrypoint
// -----------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;

    // Instantiate all our services
    let identity_service = MyIdentityService::default();
    let system_metrics = MySystemMetrics::default();
    let store_service = MyStoreService::default();

    // Configure Reflection Service
    let reflection_service = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?; // Implements grpc.reflection.v1.ServerReflection

    println!("gRPC Server listening on http://{}", addr);

    // Boot up the server and register all 4 endpoints (3 custom + 1 reflection)
    Server::builder()
        .add_service(IdentityServiceServer::new(identity_service))
        .add_service(SystemMetricsServer::new(system_metrics))
        .add_service(StoreServiceServer::new(store_service))
        .add_service(reflection_service) // Exposes the schemas to the outside world
        .serve(addr)
        .await?;

    Ok(())
}