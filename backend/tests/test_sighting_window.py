from backend.app.enrichers.sighting_window import chunked


def test_splits_into_even_batches():
    assert list(chunked(range(6), 2)) == [[0, 1], [2, 3], [4, 5]]


def test_final_batch_may_be_short():
    assert list(chunked(range(5), 2)) == [[0, 1], [2, 3], [4]]
