// Official AWS SDK for Rust compatibility suite for rocalcloud.
// Run against a server started with ENFORCE_IAM=1:
//   cd tests/rust && cargo run
use aws_credential_types::Credentials;
use aws_sdk_dynamodb::types::{AttributeDefinition, AttributeValue, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType};
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_ssm::types::ParameterType;

fn endpoint() -> String {
    std::env::var("ROCALCLOUD_URL").unwrap_or_else(|_| "http://127.0.0.1:4566".into())
}

async fn sdk_config(akid: &str, secret: &str) -> aws_config::SdkConfig {
    let creds = Credentials::new(akid, secret, None, None, "rocalcloud-test");
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region("us-east-1")
        .endpoint_url(endpoint())
        .credentials_provider(creds)
        .load()
        .await
}

async fn test_dynamodb(cfg: &aws_config::SdkConfig, run: &str) {
    let ddb = aws_sdk_dynamodb::Client::new(cfg);
    let table = format!("rs-orders-{run}");
    ddb.create_table()
        .table_name(&table)
        .billing_mode(BillingMode::PayPerRequest)
        .key_schema(KeySchemaElement::builder().attribute_name("id").key_type(KeyType::Hash).build().unwrap())
        .attribute_definitions(AttributeDefinition::builder().attribute_name("id").attribute_type(ScalarAttributeType::S).build().unwrap())
        .send().await.expect("create_table");
    ddb.put_item()
        .table_name(&table)
        .item("id", AttributeValue::S("k1".into()))
        .item("val", AttributeValue::N("99".into()))
        .send().await.expect("put_item");
    let got = ddb.get_item()
        .table_name(&table)
        .key("id", AttributeValue::S("k1".into()))
        .send().await.expect("get_item");
    assert_eq!(got.item().unwrap()["val"].as_n().unwrap(), "99");
    let cond = ddb.put_item()
        .table_name(&table)
        .item("id", AttributeValue::S("k1".into()))
        .condition_expression("attribute_not_exists(id)")
        .send().await;
    assert!(cond.is_err(), "expected ConditionalCheckFailedException");
    ddb.delete_table().table_name(&table).send().await.expect("delete_table");
}

async fn test_s3(cfg: &aws_config::SdkConfig, run: &str) {
    let s3_cfg = aws_sdk_s3::config::Builder::from(cfg).force_path_style(true).build();
    let s3 = aws_sdk_s3::Client::from_conf(s3_cfg);
    let bucket = format!("rs-bkt-{run}");
    s3.create_bucket().bucket(&bucket).send().await.expect("create_bucket");
    s3.put_object().bucket(&bucket).key("hi.txt").body(ByteStream::from_static(b"hello-rust-sdk")).send().await.expect("put_object");
    let obj = s3.get_object().bucket(&bucket).key("hi.txt").send().await.expect("get_object");
    let data = obj.body.collect().await.unwrap().into_bytes();
    assert_eq!(&data[..], b"hello-rust-sdk");
    let listed = s3.list_objects_v2().bucket(&bucket).send().await.expect("list_objects_v2");
    assert_eq!(listed.contents().len(), 1);
    assert!(s3.get_object().bucket(&bucket).key("missing.txt").send().await.is_err());
    s3.delete_object().bucket(&bucket).key("hi.txt").send().await.expect("delete_object");
    s3.delete_bucket().bucket(&bucket).send().await.expect("delete_bucket");
}

async fn test_sqs(cfg: &aws_config::SdkConfig, run: &str) {
    let sqs = aws_sdk_sqs::Client::new(cfg);
    let qname = format!("rs-q-{run}");
    let url = sqs.create_queue().queue_name(&qname).send().await.expect("create_queue").queue_url().unwrap().to_string();
    sqs.send_message().queue_url(&url).message_body("hello-sqs-rs").send().await.expect("send_message");
    let recv = sqs.receive_message().queue_url(&url).max_number_of_messages(1).send().await.expect("receive_message");
    let msg = &recv.messages()[0];
    assert_eq!(msg.body().unwrap(), "hello-sqs-rs");
    sqs.delete_message().queue_url(&url).receipt_handle(msg.receipt_handle().unwrap()).send().await.expect("delete_message");
    sqs.delete_queue().queue_url(&url).send().await.expect("delete_queue");
}

async fn test_ssm_and_iam(cfg: &aws_config::SdkConfig, run: &str) {
    let ssm = aws_sdk_ssm::Client::new(cfg);
    let pname = format!("/rs/{run}/key");
    ssm.put_parameter().name(&pname).value("v-rs").r#type(ParameterType::String).send().await.expect("put_parameter");
    assert_eq!(ssm.get_parameter().name(&pname).send().await.unwrap().parameter().unwrap().value().unwrap(), "v-rs");
    ssm.delete_parameter().name(&pname).send().await.expect("delete_parameter");

    let iam = aws_sdk_iam::Client::new(cfg);
    let uname = format!("rs-user-{run}");
    iam.create_user().user_name(&uname).send().await.expect("create_user");
    let ak = iam.create_access_key().user_name(&uname).send().await.expect("create_access_key").access_key.unwrap();
    let user_cfg = sdk_config(ak.access_key_id(), ak.secret_access_key()).await;
    let user_ssm = aws_sdk_ssm::Client::new(&user_cfg);
    assert!(user_ssm.get_parameter().name("/any").send().await.is_err(), "expected IAM implicit deny");
    iam.delete_access_key().user_name(&uname).access_key_id(ak.access_key_id()).send().await.expect("delete_access_key");
    iam.delete_user().user_name(&uname).send().await.expect("delete_user");
}

async fn test_ddb_decimal_keys(cfg: &aws_config::SdkConfig, run: &str) {
    let ddb = aws_sdk_dynamodb::Client::new(cfg);
    let table = format!("rs-num-{run}");
    ddb.create_table()
        .table_name(&table)
        .billing_mode(BillingMode::PayPerRequest)
        .key_schema(KeySchemaElement::builder().attribute_name("pk").key_type(KeyType::Hash).build().unwrap())
        .key_schema(KeySchemaElement::builder().attribute_name("sk").key_type(KeyType::Range).build().unwrap())
        .attribute_definitions(AttributeDefinition::builder().attribute_name("pk").attribute_type(ScalarAttributeType::S).build().unwrap())
        .attribute_definitions(AttributeDefinition::builder().attribute_name("sk").attribute_type(ScalarAttributeType::N).build().unwrap())
        .send().await.expect("create_table num");
    let (k1, k2) = ("90071992547409920001", "90071992547409920002");
    for k in [k2, k1] {
        ddb.put_item().table_name(&table).item("pk", AttributeValue::S("p".into())).item("sk", AttributeValue::N(k.into())).send().await.expect("put_item num");
    }
    let q = ddb.query()
        .table_name(&table)
        .key_condition_expression("pk = :p AND sk BETWEEN :a AND :b")
        .expression_attribute_values(":p", AttributeValue::S("p".into()))
        .expression_attribute_values(":a", AttributeValue::N(k1.into()))
        .expression_attribute_values(":b", AttributeValue::N(k2.into()))
        .send().await.expect("query num");
    let keys: Vec<&str> = q.items().iter().map(|i| i["sk"].as_n().unwrap().as_str()).collect();
    assert_eq!(keys, vec![k1, k2]);
    ddb.delete_table().table_name(&table).send().await.expect("delete_table num");
}

async fn test_sqs_fifo_and_delay(cfg: &aws_config::SdkConfig, run: &str) {
    let sqs = aws_sdk_sqs::Client::new(cfg);
    let qname = format!("rs-f-{run}.fifo");
    let url = sqs.create_queue()
        .queue_name(&qname)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::FifoQueue, "true")
        .attributes(aws_sdk_sqs::types::QueueAttributeName::ContentBasedDeduplication, "true")
        .send().await.expect("create fifo").queue_url().unwrap().to_string();
    sqs.send_message().queue_url(&url).message_body("dup").message_group_id("g1").send().await.expect("send1");
    sqs.send_message().queue_url(&url).message_body("dup").message_group_id("g1").send().await.expect("send2");
    let recv = sqs.receive_message().queue_url(&url).max_number_of_messages(5).send().await.expect("recv fifo");
    assert_eq!(recv.messages().len(), 1);
    assert!(sqs.send_message().queue_url(&url).message_body("bad").message_group_id("g1").delay_seconds(1).send().await.is_err());
    sqs.delete_queue().queue_url(&url).send().await.expect("delete fifo");
}

async fn test_s3_list_pagination(cfg: &aws_config::SdkConfig, run: &str) {
    let s3_cfg = aws_sdk_s3::config::Builder::from(cfg).force_path_style(true).build();
    let s3 = aws_sdk_s3::Client::from_conf(s3_cfg);
    let bucket = format!("rs-pg-{run}");
    s3.create_bucket().bucket(&bucket).send().await.expect("create_bucket pg");
    let keys = ["a/1", "a/2", "b/1", "c/1", "d.txt"];
    for k in keys {
        s3.put_object().bucket(&bucket).key(k).body(ByteStream::from_static(b"x")).send().await.expect("put pg");
    }
    let mut got_keys = vec![];
    let mut got_prefixes = vec![];
    let mut tok: Option<String> = None;
    loop {
        let mut req = s3.list_objects_v2().bucket(&bucket).delimiter("/").max_keys(2);
        if let Some(t) = &tok {
            req = req.continuation_token(t);
        }
        let resp = req.send().await.expect("list pg");
        got_keys.extend(resp.contents().iter().filter_map(|o| o.key().map(String::from)));
        got_prefixes.extend(resp.common_prefixes().iter().filter_map(|p| p.prefix().map(String::from)));
        if resp.is_truncated() == Some(true) {
            tok = resp.next_continuation_token().map(String::from);
        } else {
            break;
        }
    }
    assert_eq!(got_keys, vec!["d.txt"]);
    assert_eq!(got_prefixes, vec!["a/", "b/", "c/"]);
    for k in keys {
        s3.delete_object().bucket(&bucket).key(k).send().await.expect("del pg");
    }
    s3.delete_bucket().bucket(&bucket).send().await.expect("del bucket pg");
}

#[tokio::main]
async fn main() {
    let run = format!("{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() % 0xffff_ffff);
    let cfg = sdk_config("test", "test").await;
    test_dynamodb(&cfg, &run).await;
    println!("ok rs_dynamodb");
    test_s3(&cfg, &run).await;
    println!("ok rs_s3");
    test_sqs(&cfg, &run).await;
    println!("ok rs_sqs");
    test_ssm_and_iam(&cfg, &run).await;
    println!("ok rs_ssm_iam");
    test_ddb_decimal_keys(&cfg, &run).await;
    println!("ok rs_ddb_decimal_keys");
    test_sqs_fifo_and_delay(&cfg, &run).await;
    println!("ok rs_sqs_fifo_and_delay");
    test_s3_list_pagination(&cfg, &run).await;
    println!("ok rs_s3_list_pagination");
}
