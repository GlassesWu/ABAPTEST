*&---------------------------------------------------------------------*
*& Report ZHRSF_TEST01
*&---------------------------------------------------------------------*
*&
*&---------------------------------------------------------------------*
REPORT ZHRSF_TEST01_COP.

DATA: ls_data type zhrt_sf_001,
      gs_data TYPE zhrt_sf_001.
DATA: lv_userid(8) VALUE 'SFADMIN1',
      lv_url1 TYPE string VALUE 'https://api15.sapsf.cn/oauth/idp',
      lv_url11 TYPE string VALUE 'https://api15.sapsf.cn/odata/v2/PerPerson',
      lv_body1 TYPE string,
      lv_back1 TYPE string,
      lv_back2 TYPE string.
DATA: lt_header TYPE tihttpnvp,
      ls_header LIKE LINE OF lt_header.
DATA: go_http TYPE REF TO zhrsf_cl.

CREATE OBJECT go_http.

ls_data-clnt = '920'.
ls_data-clntid = 'YTdlNDBmYWU0N2I5Y2U5NDQzN2I1MDNkMTIyNw'.
ls_data-companyid = 'NAURAT1'.
ls_data-privatekey = 'TUlJRXZnSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2d3Z2dTa0FnRUFBb0lCQVFDWW4wcTR0V0xlRzNXSGs4SUFVbkN1bUxoaDB4ak5VL0dZeUVvd09YVTBxTHBBS0IyTkdFbjVoU'&&
'kp5ZFpQV2t1MmdqbVZVellydSt1Z1RKUnFHQWxka3BrSEJUNmFQQk1HRmw0V3BpcnVMb1BaYXoyQkZzQ3VKM3Z3WFNXWFB1NFNTY2drYVptRDFDc1RnbTJLRE53T1J6MzZHOWd3eHJJL0xMc0xudVFoclcwWUExNmJ'&&
'DQ2xMTng1b0hKTFpCSVFqNmpIdmo4T3J2WXd2L2JJbCtNVnpMcUJkTENnS3dHSEU4cWliMi91S0JJV25rVEVlZUhCRWw5WjV6SS9LcE5VcmFOMSszTkp0aUQ5Ly8zTjlOUlVEU2Jha0R6Qm5RY2VXVUtkZ0UwQksxY'&&
'nd0ejFWcVRUQVFTZng5V0luNGlrVVB2Q3c3S1IzUWVJM2RBamxyZktJc3RBZ01CQUFFQ2dnRUJBSW40eHVZQUpDYkNFQmZHZmNVb3dmRTA0c3FjdVhrMWY5MHNnOVRndkpJa1RtdWRXRW1yUVlTdXhpUnZJbjBDU29'&&
'1dzd1NGcrbzVjaU54MTJHcDVSMlFYNEszUFFiVmRDVTJwMHcyWCt6K1kvZHpPU0N2M3ZRUmdidWptVTRIZDlWVW1maEE5cVQwY3hTcC9qaWtzM0s4K014WHk3TWNqUnNMWnZSMGFhd0FSRlFNaHA4eUdJTy9nQ29Kb'&&
'01JSFdjNzgzZ29BblR5TGZVV0xmL1V4d24ydnM0bmNwdDBzQ1ArUUFXbWVDYjB2aTJNL3RtSEsyMmtIQzM4ZkdkZ0wxc2ZDM2lyWlhmSHk5alFTdVF2Qm5ndVdXdzZFbWRCMmVKMTh0OE9sNFRtT01vUUVQcW1jdU9'&&
'6dkd6WnZuTldqQS9wNHhVcUsxTnV1aVNiT2MzbjVUTEVFQ2dZRUE0SnBHblBBM08zZkNLTVZ5N0FyWHhWWURVTSt0cjcwLzdncmFFaE1kRTZNVUh2cC9DRkVUWjZ5KzdwdENqeTBVQzQ5cEdSN005aUwyTVF2cms4b'&&
'mdEYUp5bFJhUFkvSkljQWlXbWZuS0pqOW82aVpNbnZ6ZmtheGxWRG5VQ055dlMyT2UrRHlmenhXUU9KRHc2TlBEQy84YzB2RkhCcUZBMkZEeDA3MitqcGtDZ1lFQXJmVVlWMUhZczd6Ykphbm5rSS9FN3AyODRnRWh'&&
'WUDNCcHZTQmRWbmJNR29PZmw0N0hhM1JuU3lKR1E3UFowWEVPRnNIczJpdHhoRkhLb0RSQ2pmd29tNHVPYjc2U3ZVeGJFOHpYU2hkUkNlT3ZCVTRoaWZkSlRVTCtYMXRNbEZHRDQvVE1iLzlPMklOWkpGZmhLRUtXZ'&&
'zhnMUNjbzg0bXY5dmFRMDRMc0liVUNnWUJWZlVOZFh1MlcvQWx5SFYyVnpMYStUUFBzSVhCWjBPM3hmRDN1M1VtVy9ONmV2L2YwUVcvaWFWVXZXdmRscWVIVVdKekhTL3Ixd083MlVqUXp4NFk1aWxpVXVNYVJZMW9'&&
'CRXJQSUhkUzg1Q3ZaM0FRVUMrcEk5MWFHVFpDUVl2ZHgrWlE3cGsrcHNlcDRMV3NWSSswOHRyalE3YmQ4SllxYUM0MVFiQXVKR1FLQmdCeUphMy9QbG13TjNDbDJrTjAvS0lBNGNpYmxKcEdwdXgzbldHRm01elV2Q'&&
'U1lc0w2aHp2a0k1Ynhna1BOUGxOd1pEc0tTMjFHTDhySjhGV01XRFhiOVhzYytaUzdnR055QmNjY0dqZ0lGUXQvS1V6SnY5YUNMVmEreDJyZlltTFFjYWdmdlVVZmR1NDJHUEU0dFBXOEpnWHZOT3BVSW1ZUzV6VGx'&&
'qVVRtWk5Bb0dCQUltRmhicVBwU0l3QnhlQXFBN2F6N203UUZnRHQ3QUxnamJ0SHUzaHpNaUg1cTZOVzdBNG44cFBmbnpGT2dSYjcrYTk1T21MZzArcW9Mb0dqVU9PZ21KeVRwNzlMYjdpRk51WFF5b3RTNHlPQ0pRZ'&&
'WRRZUQ0S202ZGxGWVc3VWhIY05JdW1RSGtNZmhnaFdiWFFoZlNsZlFCZUpVVHVXNDU4WHZ1TGJ4SHpJbyMjI05BVVJBVDE='.

*INSERT zhrt_sf_001 FROM ls_data.

ls_header-name = 'Content-Type'.
ls_header-value = 'application/x-www-form-urlencoded'.
APPEND ls_header TO lt_header.
CLEAR ls_header.

SELECT SINGLE * FROM zhrt_sf_001 INTO gs_data WHERE CLNT = sy-mandt.
IF sy-subrc = 0.
  lv_body1 = 'client_id=' && gs_data-clntid && '&user_id=' && lv_userid && '&token_url=' && lv_url1 && '&private_key=' && gs_data-privatekey.
  PERFORM http USING lv_url1 'POST' lv_body1 CHANGING lv_back1.
  BREAK-POINT.
*  CALL METHOD go_http->post_to_sf
*    EXPORTING
*      iv_url           = lv_url1
*      iv_json          = lv_body1
*      iv_authorization =
*      iv_log_program   =
*      iv_log_others    =
*      iv_log_random    =
*    IMPORTING
*      ev_type          =
*      ev_message       =
*      ev_json          =
*      .
*CALL METHOD go_http->http_request
*  EXPORTING
*    iv_url    = lv_url11
**    iv_body   =
*    iv_method = 'GET'
**    it_header =
**  IMPORTING
**    ev_data   =
*    .
CALL METHOD go_http->generrate_bearer_token
  EXPORTING
    iv_userid       = lv_userid
  IMPORTING
*    ev_type         =
*    ev_message      =
    ev_bearer_token = lv_back2
    .

write: lv_back2.

ENDIF.

form http USING iv_url iv_method iv_body CHANGING ev_data .
    DATA: lr_http_client          TYPE REF TO if_http_client,
        lr_cx_sy_ref_is_initial TYPE REF TO cx_sy_ref_is_initial.
  DATA: l_len TYPE I.

  cl_http_client=>create_by_url(
  EXPORTING
    url                = iv_url
  IMPORTING
    client             = lr_http_client
  EXCEPTIONS
    argument_not_found = 1
    plugin_not_active  = 2
    internal_error     = 3
    OTHERS             = 4 ).

* 设置 HTTP 版本
  lr_http_client->request->set_version( if_http_request=>co_protocol_version_1_0 ).

*将HTTP代理设置请求方法 --- GET
  lr_http_client->request->set_method( iv_method ).

  lr_http_client->request->set_content_type( content_type = 'application/x-www-form-urlencoded' ).

*  IF lt_header IS NOT INITIAL.
*    lr_http_client->request->set_header_fields( lt_header ).
*  ENDIF.

  IF iv_body IS NOT INITIAL.
    l_len = strlen( iv_body ).

    CALL METHOD lr_http_client->request->set_cdata
      EXPORTING
        data   = iv_body
        offset = 0
        length = l_len.

  ENDIF.

  TRY .
      lr_http_client->send(
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2 ).

      lr_http_client->receive(
      EXCEPTIONS
        http_communication_failure = 1
        http_invalid_state         = 2
        http_processing_failed     = 3 ).
    CATCH cx_sy_ref_is_initial INTO lr_cx_sy_ref_is_initial.
  ENDTRY.

  ev_data = lr_http_client->response->get_cdata( ).

*关闭HTTP链接
  lr_http_client->close( ).
ENDFORM.
