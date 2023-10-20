from vcr import VCR

beepro_vcr = VCR(
    serializer="json",
    cassette_library_dir="tests/data/cassettes",
    path_transformer=VCR.ensure_suffix(".json"),
    match_on=["method", "scheme", "host", "port", "path"],
    filter_headers=["authorization"],
    filter_post_data_parameters=["auth", "apikey"],
)
