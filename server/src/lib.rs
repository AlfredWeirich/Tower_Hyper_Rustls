#[cfg(feature = "boxed_body")]
use http_body_util::combinators::BoxBody;

#[cfg(not(feature = "boxed_body"))]
use http_body_util::Full;

use tower::util::BoxCloneService;

use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
};
use hyper_util::service::TowerToHyperService;

pub mod error;
pub use error::SrvError;


#[cfg(feature = "boxed_body")]
pub type ServiceRespBody = BoxBody<Bytes, SrvError>;
#[cfg(not(feature = "boxed_body"))]
pub type ServiceRespBody = Full<Bytes>;

// A boxed and cloneable service object that is compatible with Hyper
pub type BoxedCloneService =
    BoxCloneService<Request<Incoming>, Response<ServiceRespBody>, SrvError>;
pub type BoxedHyperService = TowerToHyperService<BoxedCloneService>;
