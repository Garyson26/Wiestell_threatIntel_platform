from scripts.readable_counts import human_size


def test_formats_bytes_plainly():
    assert human_size(512) == "512 B"


def test_scales_to_kilobytes():
    assert human_size(2048) == "2.0 KB"
