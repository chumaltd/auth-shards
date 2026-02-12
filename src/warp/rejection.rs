use warp::reject::Reject;

#[derive(Debug)]
pub struct NoLogin {
    pub path: String,
}
impl Reject for NoLogin {}

#[derive(Debug)]
pub struct NoLoginA;
impl Reject for NoLoginA {}
