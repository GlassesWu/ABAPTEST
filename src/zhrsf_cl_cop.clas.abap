class ZHRSF_CL_COP definition
  public
  final
  create public .

public section.

  types:
    BEGIN OF ty_reptab,
        f01 TYPE string,
        f02 TYPE string,
      END OF ty_reptab .

  class-data:
    ztreplace_in  TYPE TABLE OF ty_reptab .
  class-data:
    ztreplace_out TYPE TABLE OF ty_reptab .

  methods HTTP_REQUEST
    importing
      value(IV_URL) type STRING
      value(IV_BODY) type STRING optional
      value(IV_METHOD) type STRING
      value(IT_HEADER) type TIHTTPNVP optional
    exporting
      value(EV_DATA) type STRING .
  methods POST_TO_SF
    importing
      value(IV_URL) type STRING
      value(IV_JSON) type STRING
      value(IV_AUTHORIZATION) type STRING optional
      value(IV_LOG_PROGRAM) type STRING optional
      value(IV_LOG_OTHERS) type ANY optional
      value(IV_LOG_RANDOM) type STRING optional
    exporting
      value(EV_TYPE) type CHAR1
      value(EV_MESSAGE) type STRING
      value(EV_JSON) type STRING .
  methods GENERRATE_BEARER_TOKEN
    importing
      value(IV_USERID) type ANY
    exporting
      value(EV_TYPE) type CHAR1
      value(EV_MESSAGE) type STRING
      value(EV_BEARER_TOKEN) type STRING .
  class-methods DATE_TO_UNIXTIME
    importing
      value(IV_DATE) type ANY
    exporting
      value(EV_TIMESTAMP) type STRING .
  methods ABAP_TO_JSON
    importing
      value(IV_DATA) type ANY
    exporting
      value(EV_JSON) type STRING .
  methods POST_FOR_BEARER
    importing
      value(IV_URL) type STRING
      value(IV_JSON) type STRING
      value(IV_AUTHORIZATION) type STRING optional
      value(IV_LOG_PROGRAM) type STRING optional
      value(IV_LOG_OTHERS) type ANY optional
      value(IV_LOG_RANDOM) type STRING optional
    exporting
      value(EV_TYPE) type CHAR1
      value(EV_MESSAGE) type STRING
      value(EV_JSON) type STRING .
  methods UPPERCASE_CHAR_TO_SFCASE
    importing
      value(IV_JSON) type STRING
    exporting
      value(EV_JSON) type STRING .
  methods SFCASE_CHAR_TO_UPPERCASE
    importing
      value(IV_JSON) type STRING
    exporting
      value(EV_JSON) type STRING .
  class-methods CONVERT_ABAP_TIMESTAMP_TO_JAVA
    importing
      !IV_DATE type SYDATE
      !IV_TIME type SYUZEIT default '080000'
      !IV_MSEC type NUM03 default 000
    exporting
      !EV_TIMESTAMP type STRING .
  class-methods SFUNIXTIME_TO_DATE
    importing
      !IV_SFTIMESTAMP type STRING
    exporting
      !EV_DATE type SYDATE
      !EV_TIME type SYUZEIT
      !EV_MSEC type NUM03 .
protected section.
private section.
ENDCLASS.



CLASS ZHRSF_CL_COP IMPLEMENTATION.


  METHOD ABAP_TO_JSON.

    CALL METHOD cl_fdt_json=>data_to_json
      EXPORTING
        ia_data = iv_data
      RECEIVING
        rv_json = ev_json.

  ENDMETHOD.


  METHOD CONVERT_ABAP_TIMESTAMP_TO_JAVA.

    DATA:
      lv_date           TYPE sy-datum,
      lv_days_timestamp TYPE timestampl,
      lv_secs_timestamp TYPE timestampl,
      lv_days_i         TYPE i,
      lv_sec_i          TYPE i,
      lv_timestamp      TYPE timestampl,
      lv_dummy          TYPE string.                        "#EC NEEDED

    CONSTANTS:
       lc_day_in_sec TYPE i VALUE 86400.

* Milliseconds for the days since January 1, 1970, 00:00:00 GMT
* one day has 86400 seconds
    lv_date            = '19700101'.
    lv_days_i          = iv_date - lv_date.
* Timestamp for passed days until today in seconds
    lv_days_timestamp  = lv_days_i * lc_day_in_sec.

    lv_sec_i          = iv_time.
* Timestamp for time at present day
    lv_secs_timestamp = lv_sec_i.

    lv_timestamp = ( lv_days_timestamp + lv_secs_timestamp ) * 1000.
    ev_timestamp = lv_timestamp.

    SPLIT ev_timestamp AT '.' INTO ev_timestamp lv_dummy.
    ev_timestamp = ev_timestamp + iv_msec.

*    DATA: lv_neg(1).
*    SEARCH ev_timestamp FOR '-'.
*    IF sy-subrc = 0 AND sy-fdpos <> 0.
*      SPLIT ev_timestamp AT '-' INTO ev_timestamp lv_neg.
*      CONDENSE ev_timestamp.
*      CONCATENATE '-' ev_timestamp INTO ev_timestamp.
*    ELSE.
*      CONDENSE ev_timestamp.
*    ENDIF.
*
*
    SHIFT ev_timestamp RIGHT DELETING TRAILING space.
    SHIFT ev_timestamp LEFT  DELETING LEADING space.
    IF iv_date < lv_date.
      CONCATENATE '-' ev_timestamp INTO ev_timestamp.
    ELSE.

    ENDIF.

  ENDMETHOD.


  METHOD DATE_TO_UNIXTIME.

    DATA: lv_date      TYPE datum,
          lv_timestamp TYPE string.

    lv_date = iv_date.

    IF lv_date <> '99991231'.
      CALL METHOD zhrsf_cl=>convert_abap_timestamp_to_java
        EXPORTING
          iv_date      = lv_date
        IMPORTING
          ev_timestamp = lv_timestamp.
    ELSE.
      lv_timestamp = '253402214400000'.
    ENDIF.


    CONCATENATE '/Date(' lv_timestamp ')/' INTO ev_timestamp.

  ENDMETHOD.


  METHOD GENERRATE_BEARER_TOKEN.

    DATA: lv_url1      TYPE string VALUE 'https://api15.sapsf.cn/oauth/idp',
          lv_url2      TYPE string VALUE 'https://api15.sapsf.cn/oauth/token',
          lv_body1     TYPE string,
          lv_body2     TYPE string,
          lv_assertion TYPE string,
          lv_json      TYPE string.

    TYPES: BEGIN OF ty_kv,
             access_token TYPE string,
             token_type   TYPE string,
             expires_in   TYPE string,
           END OF ty_kv.
    DATA: ls_kv TYPE ty_kv.


    DATA: ls_certificate TYPE zhrt_sf_001.
    DATA: lt_header TYPE tihttpnvp,
          ls_header LIKE LINE OF lt_header.



    SELECT SINGLE * FROM zhrt_sf_001 INTO ls_certificate WHERE clnt = sy-mandt.
    IF sy-subrc = 0.

      lv_body1 = 'client_id=' && ls_certificate-clntid && '&user_id=' && iv_userid && '&token_url=' && lv_url1 && '&private_key=' && ls_certificate-privatekey.

      CALL METHOD me->post_for_bearer
        EXPORTING
          iv_url     = lv_url1
          iv_json    = lv_body1
        IMPORTING
          ev_type    = ev_type
          ev_message = ev_message
          ev_json    = lv_assertion.

      lv_body2 = 'company_id=' && ls_certificate-companyid && '&client_id=' && ls_certificate-clntid && '&grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer' && '&user_id=' && iv_userid &&
                 '&assertion=' && lv_assertion.

      CALL METHOD me->post_for_bearer
        EXPORTING
          iv_url     = lv_url2
          iv_json    = lv_body2
        IMPORTING
          ev_type    = ev_type
          ev_message = ev_message
          ev_json    = lv_json.

      IF lv_json IS NOT INITIAL.

        CALL METHOD /ui2/cl_json=>deserialize
          EXPORTING
            json = lv_json
          CHANGING
            data = ls_kv.

        CONCATENATE ls_kv-token_type ls_kv-access_token INTO ev_bearer_token SEPARATED BY space.
        ev_type = 'S'.

      ENDIF.

    ELSE.
      ev_type = 'E'.
      ev_message = '没有为本系统配置任何SF系统秘钥'.
    ENDIF.

  ENDMETHOD.


method HTTP_REQUEST.

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

  lr_http_client->request->set_content_type( content_type = 'application/json;charset=utf-8' ).

  IF it_header IS NOT INITIAL.
    lr_http_client->request->set_header_fields( it_header ).
  ENDIF.

  IF iv_body IS NOT INITIAL.
    l_len = strlen( iv_body ).

    CALL METHOD lr_http_client->request->set_cdata
      EXPORTING
        data   = iv_body
        offset = 0
        length = l_len.

  ENDIF.

  lr_http_client->propertytype_logon_popup = 0.

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

endmethod.


METHOD POST_FOR_BEARER.

  DATA: l_authorization TYPE string.
  DATA: lt_header TYPE tihttpnvp,
        ls_header LIKE LINE OF lt_header.

  DATA: lo_cx_xslt_format_error TYPE REF TO cx_xslt_format_error,
        lo_cx_xslt_runtime_error TYPE REF TO cx_xslt_runtime_error.
  DATA: lv_log_others TYPE string.

  ls_header-name = 'Content-Type'.
  ls_header-value = 'application/x-www-form-urlencoded'.
  APPEND ls_header TO lt_header.
  CLEAR ls_header.
*
  CALL METHOD me->http_request
    EXPORTING
      iv_url    = iv_url
      iv_method = 'POST'
      it_header = lt_header
      iv_body   = iv_json
    IMPORTING
      ev_data   = ev_json.

ENDMETHOD.


METHOD POST_TO_SF.

  DATA: l_authorization TYPE string.
  DATA: lt_header TYPE tihttpnvp,
        ls_header LIKE LINE OF lt_header.
  DATA: ls_replace TYPE ty_reptab,
        lt_replace LIKE ztreplace_out.
*  DATA: lt_json_return TYPE TABLE OF zhrsf0001_s,
*        ls_json_return TYPE zhrsf0001_s.
  DATA: lo_cx_xslt_format_error TYPE REF TO cx_xslt_format_error,
        lo_cx_xslt_runtime_error TYPE REF TO cx_xslt_runtime_error.
  DATA: lv_log_others TYPE string.

  DEFINE df_replace.
    ls_replace-f01 = &1.
    ls_replace-f02 = &2.
    append ls_replace to lt_replace.
  END-OF-DEFINITION.

*
  REFRESH lt_replace.
  df_replace '""' 'null' .
  df_replace '"__metadata"' '"__metadata"' .
  df_replace '"uri"' '"uri"' .
  df_replace '"type"' '"type"' .
  APPEND LINES OF lt_replace TO ztreplace_out.
  LOOP AT ztreplace_out INTO ls_replace. "统一转换大小写
    REPLACE ALL OCCURRENCES OF ls_replace-f01 IN iv_json WITH ls_replace-f02 IGNORING CASE.
  ENDLOOP.

  CALL METHOD me->http_request
    EXPORTING
      iv_url    = iv_url
      iv_method = 'POST'
      it_header = lt_header
      iv_body   = iv_json
    IMPORTING
      ev_data   = ev_json.

*  IF ev_json IS NOT INITIAL.
*    REPLACE ALL OCCURRENCES OF '"d"' IN ev_json WITH  '"D"' IGNORING CASE.
*    REPLACE ALL OCCURRENCES OF '"status"' IN ev_json WITH  '"STATUS"' IGNORING CASE.
*    REPLACE ALL OCCURRENCES OF '"editstatus"' IN ev_json WITH  '"EDITSTATUS"' IGNORING CASE.
*    REPLACE ALL OCCURRENCES OF '"message"' IN ev_json WITH  '"MESSAGE"' IGNORING CASE.
*    TRY .
*        CALL TRANSFORMATION id SOURCE XML ev_json RESULT d = lt_json_return.
*        READ TABLE lt_json_return INTO ls_json_return INDEX 1.
*        IF ls_json_return-status = 'OK'.
*          ev_type = 'S'.
*        ELSE.
*          ev_type = 'E'.
*          ev_message = ls_json_return-message.
*        ENDIF.
*      CATCH cx_xslt_format_error INTO lo_cx_xslt_format_error.
*        ev_type = 'E'.
*        ev_message = lo_cx_xslt_format_error->get_text( ).
*      CATCH cx_xslt_runtime_error INTO lo_cx_xslt_runtime_error.
*        ev_type = 'E'.
*        ev_message = lo_cx_xslt_runtime_error->get_text( ).
*    ENDTRY.
*
*  ELSE.
*    ev_type = 'E'.
*    ev_message = '无返回'.
*  ENDIF.

ENDMETHOD.


  METHOD SFCASE_CHAR_TO_UPPERCASE.

    DATA: ls_replace TYPE ty_reptab.

    LOOP AT ztreplace_in INTO ls_replace.
      REPLACE ALL OCCURRENCES OF ls_replace-f01 IN iv_json WITH ls_replace-f02 IGNORING CASE.
    ENDLOOP.

  ENDMETHOD.


  METHOD SFUNIXTIME_TO_DATE.

    DATA:
      lv_date        TYPE sy-datum,
      lv_days_i      TYPE i,
      lv_sec_i       TYPE i,
      lv_timestamp   TYPE timestampl,
      lv_timsmsec    TYPE timestampl,
      lv_sftimestamp TYPE string.
    DATA: lt_result_tab TYPE match_result_tab,
          ls_result_tab LIKE LINE OF lt_result_tab.
    CONSTANTS:
      lc_day_in_sec TYPE i VALUE 86400.


    FIND ALL OCCURRENCES OF REGEX '\d*'
         IN iv_sftimestamp RESULTS lt_result_tab.

    IF lt_result_tab IS NOT INITIAL.
      DELETE lt_result_tab WHERE length <= 4.

      READ TABLE lt_result_tab INTO ls_result_tab INDEX 1.

      lv_sftimestamp = iv_sftimestamp+ls_result_tab-offset(ls_result_tab-length).

* IV_TIMESTAMP stores milliseconds since January 1, 1970, 00:00:00 GMT
      lv_timestamp = lv_sftimestamp / 1000.   "timestamp in seconds
* One day has 86400 seconds: Timestamp in days
      lv_days_i    = lv_timestamp DIV lc_day_in_sec.
      lv_date      = '19700101'.
      ev_date     = lv_date + lv_days_i.
* Rest seconds (timestamp - days)
      lv_sec_i    = lv_timestamp MOD lc_day_in_sec.
      ev_time     = lv_sec_i.
* Rest sec and milli seconds
      lv_timsmsec  = lv_timestamp MOD lc_day_in_sec.
      lv_timsmsec  = lv_timsmsec - lv_sec_i.
      ev_msec      = lv_timsmsec * 1000.

    ELSE.
      ev_date = '19700101'.
    ENDIF.

  ENDMETHOD.


  METHOD UPPERCASE_CHAR_TO_SFCASE.

    DATA: ls_replace TYPE ty_reptab.

    LOOP AT ztreplace_out INTO ls_replace.
      REPLACE ALL OCCURRENCES OF ls_replace-f01 IN iv_json WITH ls_replace-f02 IGNORING CASE.
    ENDLOOP.

  ENDMETHOD.
ENDCLASS.
