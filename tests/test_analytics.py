import pytest
from vk_mcp.analytics import compare_samples
from vk_mcp.catalog import PolicyError


def post(i,date=100,**extra):
    return {"id":i,"owner_id":-1,"date":date,**extra}


def test_missing_metrics_are_not_invented_and_duplicates_pins_excluded():
    samples=[{"group_id":1,"members_count":100,"posts":[
        post(1,likes={"count":10},comments={"count":2},reposts={"count":3},views={"count":100}),
        post(2,likes={"count":0}),post(1),post(3,is_pinned=1),post(4,date=1000)]}]
    report=compare_samples(samples,0,200)
    row=report["communities"][0]
    assert row["sample_posts"]==2
    assert row["metrics"]["likes"]["median"]==5
    assert row["metrics"]["views"]["missing_posts"]==1
    assert row["er_views_median_percent"]==15
    assert row["er_views_posts"]==1
    assert row["er_current_members_median_percent"]==15
    assert len(row["post_sources"])==2


def test_no_data_stays_null_and_zero_denominator_is_not_used():
    report=compare_samples([{"group_id":1,"members_count":0,"posts":[post(1,views={"count":0},likes={"count":0},comments={"count":0},reposts={"count":0})]}],0,200)
    assert report["communities"][0]["er_views_median_percent"] is None
    assert report["communities"][0]["er_current_members_median_percent"] is None
    assert compare_samples([{"group_id":1,"posts":[]}],0,200)["communities"][0]["metrics"]["likes"]["sum"] is None


def test_owner_mismatch_and_invalid_period_are_rejected():
    with pytest.raises(PolicyError): compare_samples([{"group_id":2,"posts":[post(1)]}],0,200)
    with pytest.raises(PolicyError): compare_samples([{"group_id":1,"posts":[]}],200,200)
