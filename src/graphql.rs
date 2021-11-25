use graphql_client::{GraphQLQuery, Response};
use std::collections::HashMap;

// Since other types are too complex,
// or, more specifically, chrono::DateTime doesn't
// implement serde's Deserialize (which makes sense).
type DateTime = String;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/attendance-rs-schema.graphql",
    query_path = "graphql/log-attendance.graphql"
)]
pub struct LogAttendance;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/attendance-rs-schema.graphql",
    query_path = "graphql/create-user.graphql"
)]
pub struct CreateUser;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/attendance-rs-schema.graphql",
    query_path = "graphql/list-users.graphql"
)]
pub struct ListUsers;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/attendance-rs-schema.graphql",
    query_path = "graphql/user-by-uuid.graphql"
)]
pub struct UserByUuid;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "graphql/attendance-rs-schema.graphql",
    query_path = "graphql/update-user-alt-id.graphql"
)]
pub struct UpdateUserAltID;
