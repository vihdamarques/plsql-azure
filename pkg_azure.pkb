create or replace package body pkg_azure as
  g_token_cache   t_token;
  --
  g_tenant_id     varchar2(255);
  g_client_id     varchar2(255);
  g_client_secret varchar2(255);
  g_wallet_path   varchar2(500);
  g_wallet_pass   varchar2(255);
  --
  procedure set_config(p_tenant_id     in varchar2,
                       p_client_id     in varchar2,
                       p_client_secret in varchar2,
                       p_wallet_path   in varchar2 default null,
                       p_wallet_pass   in varchar2 default null) is
  begin
    g_tenant_id     := p_tenant_id;
    g_client_id     := p_client_id;
    g_client_secret := p_client_secret;
    g_wallet_path   := p_wallet_path;
    g_wallet_pass   := p_wallet_pass;
  end set_config;

  function unix_timestamp_to_date(p_unix_timestamp number) return date is
      c_base_date      constant date   := to_date('1970-01-01', 'YYYY-MM-DD');
      c_seconds_in_day constant number := 24 * 60 * 60;
      l_date           date;
  begin
    if (p_unix_timestamp < 0) then
      raise_application_error(-20001, 'unix_timestamp cannot be nagative');
    end if;

    l_date := cast((from_tz(cast(
                c_base_date + (p_unix_timestamp / c_seconds_in_day)
               as timestamp), 'GMT') at time zone sessiontimezone) as date);

    return l_date;
  end unix_timestamp_to_date;

  function format_RFC1123(p_timestamp in timestamp with time zone) return varchar2 is
  begin
    return to_char (
             p_timestamp at time zone 'GMT',
             'Dy"," dd Mon yyyy hh24:mi:ss TZR',
             'NLS_DATE_LANGUAGE=''ENGLISH'''
           );
  end format_RFC1123;

  function convert_RFC1123(p_timestamp in varchar2) return timestamp with time zone is
  begin
    return cast (
             to_timestamp_tz (
               p_timestamp,
               'Dy"," dd Mon yyyy hh24:mi:ss TZR',
               'NLS_DATE_LANGUAGE=''ENGLISH'''
             ) at time zone sessiontimezone
             as date
           );
  end convert_RFC1123;

  procedure make_request(p_url               in varchar2,
                         p_headers           in t_headers,
                         p_method            in varchar2 default 'GET',
                         p_payload           in varchar2 default null,
                         p_payload_blob      in blob     default null,
                         p_response_headers out t_headers,
                         p_response_binary  out blob) is
    c_timeout  constant number(6) := 240000;
    --
    l_request          utl_http.req;
    l_response         utl_http.resp;
    --
    l_header_name    s_name;
    l_header_value   s_value;
    --
    l_url             varchar2(500);
    l_raw_chunk       raw(32767);
    l_response_binary blob;
  begin
    --
    utl_http.set_transfer_timeout(c_timeout);
    --utl_http.set_body_charset('UTF-8');
    --
    if lower(p_url) like 'https%' then
      if g_wallet_path is not null then
        utl_http.set_wallet(g_wallet_path, g_wallet_pass);
      else
        raise_application_error(-20001, 'Wallet not set');
      end if;
    end if;
    --
    l_url := utl_url.escape(p_url, false, 'UTF-8');
    --
    dbms_output.put_line('----- Request Begin -----');
    dbms_output.put_line('URL: '    || l_url);
    dbms_output.put_line('Method: ' || p_method);
    l_request := utl_http.begin_request(l_url, p_method, utl_http.HTTP_VERSION_1_1);
    --
    if p_headers.count > 0 then
      dbms_output.put_line('----- Request Headers -----');
      l_header_name := p_headers.first;
      loop
        exit when l_header_name is null;
        utl_http.set_header(r => l_request, name => l_header_name, value => p_headers(l_header_name));
        dbms_output.put_line(l_header_name || ': ' || p_headers(l_header_name));
        l_header_name := p_headers.next(l_header_name);
      end loop;
    end if;
    --
    if p_payload is not null then
      utl_http.write_text(r => l_request, data => p_payload);
    end if;
    --
    if p_payload_blob is not null then
      for i in 1 .. ceil(dbms_lob.getlength(p_payload_blob)/2000) loop
        utl_http.write_raw(r => l_request, data => dbms_lob.substr(p_payload_blob, 2000, (2000 * (i - 1)) + 1));
      end loop;
    end if;
    --
    l_response := utl_http.get_response(l_request);
    --
    dbms_output.put_line('----- Response Headers -----');
    for i in 1 .. nvl(utl_http.get_header_count(l_response), 0) loop
      utl_http.get_header (
        l_response,
        i,
        l_header_name,
        l_header_value
      );
      p_response_headers(l_header_name) := l_header_value;
      dbms_output.put_line(l_header_name || ': ' || l_header_value);
    end loop;
    --
    dbms_output.put_line('----- Response Code -----');
    dbms_output.put_line(l_response.status_code || ' - ' || l_response.reason_phrase);
    if l_response.status_code not like '2%' then
      utl_http.end_response(l_response);
      raise_application_error(-20001, 'Error ' || l_response.status_code || ' - ' || l_response.reason_phrase);
    else -- Reads data
      dbms_lob.createTemporary(l_response_binary, TRUE);
      --
      begin
        loop
          utl_http.read_raw(l_response, l_raw_chunk, 32767);
          dbms_lob.writeAppend(lob_loc => l_response_binary, amount => utl_raw.length(l_raw_chunk), buffer => l_raw_chunk);
        end loop;
      exception
        when utl_http.end_of_body then null;
        --when others then null;
      end;
      --
      utl_http.end_response(l_response);
      dbms_output.put_line('----- Request End -----');
      --
      p_response_binary := l_response_binary;
      --
      dbms_lob.freetemporary(l_response_binary);
    end if;
  end make_request;

  function binary_request(p_url          in varchar2,
                          p_headers      in t_headers,
                          p_method       in varchar2 default 'GET',
                          p_payload      in varchar2 default null,
                          p_payload_blob in blob     default null) return r_binary_response is
    l_response_binary  blob;
    l_response_headers t_headers;
    l_response         r_binary_response;
  begin
    make_request (
      p_url,
      p_headers,
      p_method,
      p_payload,
      p_payload_blob,
      l_response_headers,
      l_response_binary
    );
    --
    if l_response_headers.exists('Content-Type') then
      l_response.mime_type := nvl(regexp_substr(l_response_headers('Content-Type'), '[^;]+', 1, 1), 'application/octet-stream');
    end if;
    --
    if l_response_headers.exists('Content-Disposition') then
      l_response.file_name := regexp_replace(l_response_headers('Content-Disposition'), '(.+filename=")(.+)(")', '\2');
    end if;
    --
    l_response.file_data := l_response_binary;
    --
    return l_response;
  end binary_request;

  function text_request(p_url          in varchar2,
                        p_headers      in t_headers,
                        p_method       in varchar2 default 'GET',
                        p_payload      in varchar2 default null,
                        p_payload_blob in blob     default null,
                        p_charset      in varchar2 default 'AL32UTF8') return r_text_response is
    l_binary_response  r_binary_response;
    l_response         r_text_response;
    --
    l_clob         clob;
    l_clob_offset  integer := 1;
    l_blob_offset  integer := 1;
    l_amount       integer := dbms_lob.lobmaxsize;
    l_lang_context number  := dbms_lob.default_lang_ctx;
    l_warning      integer;
  begin
    l_binary_response := binary_request(p_url          => p_url,
                                        p_headers      => p_headers,
                                        p_method       => p_method,
                                        p_payload      => p_payload,
                                        p_payload_blob => p_payload_blob);
    --
    dbms_lob.createTemporary(l_clob, true);
    dbms_lob.open(l_clob, dbms_lob.lob_readwrite);
    --
    if nvl(dbms_lob.getlength(l_binary_response.file_data), 0) > 0 then
      if dbms_lob.substr(l_binary_response.file_data, 3, 1) = hextoraw('EFBBBF') then -- UTF-8 with BOM
        l_blob_offset := 4;
        l_amount      := dbms_lob.getlength(l_binary_response.file_data) - 3;
      end if;
      --
      dbms_lob.convertToClob(l_clob
                            ,l_binary_response.file_data
                            ,l_amount
                            ,l_clob_offset
                            ,l_blob_offset
                            ,nls_charset_id(p_charset) --dbms_lob.default_csid
                            ,l_lang_context
                            ,l_warning);
    end if;
    --
    l_response.text_data := l_clob;
    l_response.mime_type := l_binary_response.mime_type;
    --
    dbms_lob.close(l_clob);
    dbms_lob.freeTemporary(l_clob);
    --
    return l_response;
  end text_request;

  function cached_token_is_valid(p_tenant_id in varchar2, p_client_id in varchar2, p_resource in varchar2) return boolean is
  begin
    if g_token_cache.exists(p_tenant_id) and
       g_token_cache(p_tenant_id).exists(p_client_id) and
       g_token_cache(p_tenant_id)(p_client_id).exists(p_resource) and
       g_token_cache(p_tenant_id)(p_client_id)(p_resource).token is not null and
       g_token_cache(p_tenant_id)(p_client_id)(p_resource).expires_on > sysdate
    then
      return true;
    else
      return false;
    end if;
  end cached_token_is_valid;

  function authenticate(p_resource      in varchar2,
                        p_force         in boolean  default false,
                        p_tenant_id     in varchar2 default g_tenant_id,
                        p_client_id     in varchar2 default g_client_id,
                        p_client_secret in varchar2 default g_client_secret) return varchar2 is
    c_grant_type constant varchar2(20)  := 'client_credentials';
    --
    l_headers    t_headers;
    l_response   r_text_response;
    l_payload    varchar2(32767);
    --
    l_url_token  varchar2(255);
    --
    l_error      varchar2(32767);
    l_token      varchar2(32767);
    l_expires_on date;
  begin
    if p_tenant_id is null or p_client_id is null or p_client_secret is null then
      raise_application_error(-20001, 'tenant_id, client_id and client_secret are mandatory. Please call set_config before making a request.');
    end if;
    --
    if not p_force and cached_token_is_valid(p_tenant_id, p_client_id, p_resource) then
      return g_token_cache(p_tenant_id)(p_client_id)(p_resource).token;
    end if;
    --
    l_url_token     := 'https://login.microsoftonline.com/' || p_tenant_id || '/oauth2/token';
    --
    l_payload := 'grant_type='    || c_grant_type    || chr(38) ||
                 'client_id='     || p_client_id     || chr(38) ||
                 'client_secret=' || p_client_secret || chr(38) ||
                 'resource='      || utl_url.escape(p_resource, true);
    --
    l_headers('User-Agent')     := 'Mozilla/5.0';
    l_headers('Content-Type')   := 'application/x-www-form-urlencoded';
    l_headers('Content-Length') := to_char(length(l_payload));
    --
    l_response := text_request (
      p_url     => l_url_token,
      p_headers => l_headers,
      p_method  => 'POST',
      p_payload => l_payload
    );
    --
    apex_json.parse(l_response.text_data);
    l_error := apex_json.get_varchar2('error_description');
    --
    if l_error is not null then
      raise_application_error(-20001, l_error);
    else
      l_token      := apex_json.get_varchar2('access_token');
      l_expires_on := unix_timestamp_to_date(apex_json.get_varchar2('expires_on'));
      --
      g_token_cache(p_tenant_id)(p_client_id)(p_resource).token      := l_token;
      g_token_cache(p_tenant_id)(p_client_id)(p_resource).expires_on := l_expires_on;
      --
      return l_token;
    end if;
  end authenticate;

  function keyvault_get_secret(p_vault_name in varchar2, p_secret_name in varchar2) return varchar2 is
    l_headers  t_headers;
    l_response r_text_response;
    l_token    varchar2(32767);
    l_url      varchar2(500);
    --
    l_response_body varchar2(32767);
    l_error         varchar2(32767);
    l_secret        varchar2(32767);
  begin
    l_token := authenticate(p_resource => RESOURCE_KEYVAULT);
    l_url   := apex_string.format('https://%s.vault.azure.net/secrets/%s?api-version=%s', p_vault_name, p_secret_name, API_VERSION_KEYVAULT);
    l_headers('Authorization') := 'Bearer ' || l_token;
    --
    l_response := text_request (
      p_url     => l_url,
      p_method  => 'GET',
      p_headers => l_headers
    );
    --
    apex_json.parse(l_response.text_data);
    --
    l_error := apex_json.get_varchar2('error.message');
    if l_error is not null then
      raise_application_error(-20001, l_error);
    else
      l_secret := apex_json.get_varchar2('value');
    end if;
    --
    return l_secret;
  end keyvault_get_secret;

  function storage_list_blobs(p_account in varchar2, p_container in varchar2, p_prefix in varchar2) return t_blob_list is
    l_response    r_text_response;
    l_headers     t_headers;
    l_headers_adp t_headers;
    l_token       varchar2(32767);
    l_resource    varchar2(255);
    l_url         varchar2(255);
    --
    l_timestamp   varchar2(255);
    --
    l_xml         XMLType;
    l_blob_list   t_blob_list := t_blob_list();
  begin
    l_timestamp := format_RFC1123(systimestamp);
    l_resource  := apex_string.format(RESOURCE_BLOB, p_account);
    l_url       := apex_string.format('%s/%s?restype=container&comp=list&prefix=%s', l_resource, p_container, p_prefix);
    l_token     := authenticate(p_resource => l_resource);
    --
    l_headers('Authorization') := 'Bearer ' || l_token;
    l_headers('x-ms-version')  := API_VERSION_STORAGE;
    l_headers('x-ms-date')     := l_timestamp;
    --
    l_response := text_request (
      p_url     => l_url,
      p_method  => 'GET',
      p_headers => l_headers
    );
    --
    l_xml := XMLType(l_response.text_data);

    for i in (
      select *
        from xmltable (
           '/EnumerationResults/Blobs/Blob'
           passing l_xml
           columns
             file_name      varchar2(255) path 'Name',
             creation_time  varchar2(255) path 'Properties/Creation-Time',
             last_modified  varchar2(255) path 'Properties/Last-Modified',
             content_length varchar2(255) path 'Properties/Content-Length',
             content_type   varchar2(255) path 'Properties/Content-Type'
         )
    ) loop
      l_blob_list.extend;
      l_blob_list(l_blob_list.count).file_name      := i.file_name;
      l_blob_list(l_blob_list.count).creation_time  := convert_RFC1123(i.creation_time);
      l_blob_list(l_blob_list.count).last_modified  := convert_RFC1123(i.last_modified);
      l_blob_list(l_blob_list.count).content_length := to_number(i.content_length);
      l_blob_list(l_blob_list.count).content_type   := i.content_type;
    end loop;

    return l_blob_list;
  end storage_list_blobs;

  function storage_get_blob(p_account in varchar2, p_container in varchar2, p_blob_name in varchar2) return blob is
    l_response    r_binary_response;
    l_headers     t_headers;
    l_token       varchar2(32767);
    l_resource    varchar2(255);
    l_url         varchar2(255);
    --
    l_timestamp   varchar2(255);
  begin
    l_timestamp := format_RFC1123(systimestamp);
    l_resource  := apex_string.format(RESOURCE_BLOB, p_account);
    l_url       := apex_string.format('%s/%s/%s', l_resource, p_container, p_blob_name);
    l_token     := authenticate(p_resource => l_resource);
    --
    l_headers('Authorization') := 'Bearer ' || l_token;
    l_headers('x-ms-version')  := API_VERSION_STORAGE;
    l_headers('x-ms-date')     := l_timestamp;
    --
    l_response := binary_request (
      p_url     => l_url,
      p_method  => 'GET',
      p_headers => l_headers
    );

    return l_response.file_data;
  end storage_get_blob;

  procedure storage_put_blob(p_account   in varchar2,
                             p_container in varchar2,
                             p_blob_name in varchar2,
                             p_content   in blob,
                             p_mime_type in varchar2 default null) is
    l_response    r_text_response;
    l_headers     t_headers;
    l_token       varchar2(32767);
    l_resource    varchar2(255);
    l_url         varchar2(255);
    l_timestamp   varchar2(255);
    --
    l_length      number := nvl(dbms_lob.getlength(p_content), 0);
  begin
    if l_length = 0 then
      raise_application_error(-20001, 'Empty File');
    end if;
    --
    l_timestamp := format_RFC1123(systimestamp);
    l_resource  := apex_string.format(RESOURCE_BLOB, p_account);
    l_url       := apex_string.format('%s/%s/%s', l_resource, p_container, p_blob_name);
    l_token     := authenticate(p_resource => l_resource);
    --
    l_headers('Authorization')  := 'Bearer ' || l_token;
    l_headers('x-ms-version')   := API_VERSION_STORAGE;
    l_headers('x-ms-date')      := l_timestamp;
    l_headers('x-ms-blob-type') := 'BlockBlob';
    l_headers('Content-Length') := l_length;
    --
    if p_mime_type is not null then
      l_headers('Content-Type') := p_mime_type;
    end if;
    --
    l_response := text_request (
      p_url     => l_url,
      p_method  => 'PUT',
      p_headers => l_headers,
      p_payload_blob => p_content
    );
  end storage_put_blob;
end pkg_azure;
/