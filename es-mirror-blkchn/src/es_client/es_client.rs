pub struct ElasticSearchClient {
    api_key: String,
    es_address: String,
}

impl ElasticSearchClient {
    fn new(es_address: String, api_key: String) -> ElasticSearchClient {
        ElasticSearchClient {
            api_key,
            es_address,
        }
    }
}
